from array import array
from base64 import b32decode, b32encode, b64decode, b64encode
from datetime import datetime, timedelta
import hashlib
import hmac
import logging
import os
import pickle
from urllib import urlencode
import urlparse

from flask import Flask, g, make_response, redirect, render_template, request, session, url_for
from flask.views import MethodView
import psycopg2

from dh import DiffieHellman


class DefaultSettings(object):
    DEBUG = True
    DSN = 'dbname=flid'

default_settings = DefaultSettings()


app = Flask(__name__)
app.config.from_object('flid.default_settings')
if 'FLID_SETTINGS' in os.environ:
    app.config.from_envvar('FLID_SETTINGS')


@app.before_request
def before_request():
    g.db_conn = psycopg2.connect(app.config['DSN'])

@app.teardown_request
def teardown_request(exc):
    g.db_conn.close()
    del g.db_conn

def btwoc(val):
    """Return the given value in big-endian two's complement format."""
    if val == 0:
        return '\x00'
    return ''.join(reversed(pickle.encode_long(val)))

def unbtwoc(text):
    return pickle.decode_long(''.join(reversed(text)))

def xor(a, b):
    abytes = array('B', a)
    bbytes = array('B', b)
    for i in range(len(abytes)):
        abytes[i] ^= bbytes[i]
    return abytes.tostring()

def kv(items):
    return ''.join("%s:%s\n" % (key, value) for key, value in items)

def openid_prefix(items):
    for k, v in items:
        yield ('openid.' + k, v)

def direct_response(**kwargs):
    items = kwargs.items()
    items.append(('ns', 'http://specs.openid.net/auth/2.0'))
    return kv(items), 400 if 'error' in kwargs else 200, {'Content-Type': 'text/plain'}

def indirect_response(request_args, **kwargs):
    try:
        return_to = request_args['openid.return_to']
    except KeyError:
        return direct_response(error='Error generating indirect response (no return_to)')
    kwargs['ns'] = 'http://specs.openid.net/auth/2.0'
    if 'error' in kwargs:
        kwargs['mode'] = 'error'

    sep = '&' if '?' in return_to else '?'
    resp_args = (('openid.' + key, value) for key, value in kwargs.iteritems())
    resp = urlencode(tuple(resp_args))
    return redirect(sep.join((return_to, resp)))


class ServerEndpoint(MethodView):

    def get(self):
        if not any(x in request.args for x in ('openid.ns', 'openid.mode', 'openid.return_to')):
            # Probably someone in a browser, so say hi.
            return render_template('about.html')

        version = request.args.get('openid.ns')
        if not version or version != 'http://specs.openid.net/auth/2.0':
            return indirect_response(request.args, error="This server supports OpenID 2.0 only")

        try:
            mode = request.args['openid.mode']
        except KeyError:
            return indirect_response(request.args, error="No openid.mode provided")

        if mode == 'checkid_immediate':
            # No immediate requests are allowed.
            # TODO: remember some whitelisted realms?
            return indirect_response(request.args, mode='setup_needed')
        elif mode == 'checkid_setup':
            return self.checkid(request.args)

        return indirect_response(request.args, error="Unknown openid.mode provided")

    def checkid(self, args):
        assoc_handle = args.get('openid.assoc_handle')
        if assoc_handle is None:
            logging.info("Relying party didn't associate first OH WELL <3")

        realm = args.get('openid.realm') or args.get('openid.return_to')
        if realm is None:
            return indirect_response(args, error="No realm provided")

        try:
            claimed_id = args['openid.claimed_id']
        except KeyError:
            return indirect_response(args, error="No claimed ID provided")
        try:
            identity = args['openid.identity']
        except KeyError:
            return indirect_response(args, error="No local identifier (openid.identity) provided")
        if identity == 'http://specs.openid.net/auth/2.0/identifier_select':
            return indirect_response(args, error="Identifier selection is not supported")
        if identity != claimed_id:
            return indirect_response(args, error="Requested local identifier does not match the claimed identifier? what is this i don't even lol")

        try:
            csrf_token = session['csrf_token']
        except KeyError:
            csrf_token = session['csrf_token'] = os.urandom(24)
        csrf_token = b32encode(csrf_token)
        return render_template('decide.html',
            realm=realm,
            identity=identity,
            request_args=urlencode(args),
            csrf_token=csrf_token)

    def post(self):
        version = request.form.get('openid.ns')
        if not version or version != 'http://specs.openid.net/auth/2.0':
            return direct_response(error="This server supports OpenID 2.0 only")

        try:
            mode = request.form['openid.mode']
        except KeyError:
            return direct_response(error="No openid.mode provided")

        if mode == 'associate':
            return self.associate()
        elif mode == 'check_authentication':
            return self.direct_verify()
        elif mode == 'checkid_setup':
            return self.checkid(request.form)

        return direct_response(error="Unknown openid.mode provided")

    def associate(self):
        assoc_type = request.form.get('openid.assoc_type')
        if assoc_type not in ('HMAC-SHA1', 'HMAC-SHA256'):
            return err_response(
                error="Unknown association type requested",
                error_code="unsupported-type",
                assoc_type="HMAC-SHA256",
                session_type="DH-SHA256",
            )

        session_type = request.form.get('openid.session_type')
        if session_type == 'no-encryption':
            # TODO: support no-encryption if we can tell we're on SSL?
            return err_response(
                error="Session type no-encryption is not supported on non-HTTPS connections",
                error_code="unsupported-type",
                assoc_type="HMAC-SHA256",
                session_type="DH-SHA256",
            )
        if session_type not in ('DH-SHA1', 'DH-SHA256'):
            return err_response(
                error="Unknown session type requested",
                error_code="unsupported-type",
                assoc_type="HMAC-SHA256",
                session_type="DH-SHA256",
            )

        mac_key = os.urandom(20 if assoc_type == 'HMAC-SHA1' else 32)
        assoc_handle = b64encode(os.urandom(20))
        expires = datetime.utcnow() + timedelta(seconds=1000)

        logging.debug("Formed a shared association %s with key %r!", assoc_handle, mac_key)

        cur = g.db_conn.cursor()
        cur.execute("INSERT INTO openid_associations (handle, private, secret, assoc_type, expires) VALUES (%s, false, %s, %s, %s)",
            (assoc_handle, bytearray(mac_key), assoc_type, expires))
        g.db_conn.commit()
        cur.close()

        dh_mod = request.form.get('openid.dh_modulus')
        dh_gen = request.form.get('openid.dh_gen')
        if dh_mod is not None:
            dh_mod = unbtwoc(b64decode(dh_mod))
        if dh_gen is not None:
            dh_gen = unbtwoc(b64decode(dh_gen))

        try:
            dh_consumer_public = request.form['openid.dh_consumer_public']
        except KeyError:
            return err_response(error="Required parameter dh_consumer_public not provided")
        dh_consumer_public = unbtwoc(b64decode(dh_consumer_public))

        dh = DiffieHellman(dh_gen, dh_mod, dh_consumer_public)
        dh.select_key()
        dh_server_public = b64encode(btwoc(dh.calculate_public_key()))
        dh_secret = dh.calculate_secret()

        hasher = hashlib.sha1 if session_type == 'DH-SHA1' else hashlib.sha256
        hashed_session_key = hasher(btwoc(dh_secret)).digest()
        cipher_key_bytes = xor(hashed_session_key, mac_key)
        enc_mac_key = b64encode(cipher_key_bytes)

        return direct_response(
            assoc_type=assoc_type,
            session_type=session_type,
            assoc_handle=assoc_handle,
            expires_in=1000,
            dh_server_public=dh_server_public,
            enc_mac_key=enc_mac_key,
        )

    def direct_verify(self):
        # What association did we use?
        try:
            assoc_handle = request.form['openid.assoc_handle']
        except KeyError:
            logging.info("A direct verifier specified no association handle")
            return direct_response(is_valid='false')

        cur = g.db_conn.cursor()
        cur.execute("SELECT secret, assoc_type FROM openid_associations WHERE handle = %s AND private IS TRUE AND %s < expires",
            (assoc_handle, datetime.utcnow()))
        result = cur.fetchone()
        if result is None:
            logging.info("A direct verifier specified an invalid association handle %r", assoc_handle)
            return direct_response(is_valid='false', invalidate_handle=assoc_handle)
        mac_key, assoc_type = result
        cur.close()

        # What fields did we sign?
        try:
            signed = request.form['openid.signed']
        except KeyError:
            logging.info("A direct verified specified no 'signed' field")
            return direct_response(is_valid='false')
        signed_fields = signed.split(',')

        try:
            resp_items = list((k, request.form['openid.' + k]) for k in signed_fields)
        except KeyError, exc:
            logging.info("A direct verifier specified a signed field containing %r but no %r field in the response", str(exc), str(exc))
            return direct_response(is_valid='false')
        plaintext = kv(openid_prefix(resp_items))

        # SIGN 'EM
        digestmod = hashlib.sha1 if assoc_type == 'HMAC-SHA1' else hashlib.sha256  # it'll be 256
        signer = hmac.new(mac_key, plaintext, digestmod)
        expected_signature = b64encode(signer.digest())

        try:
            signature = request.form['openid.sig']
        except KeyError:
            logging.info("A direct verifier specified no signature")
            return direct_response(is_valid='false')

        if signature == expected_signature:
            # Yay yay!
            logging.info("A direct verifier successfully verified!")
            return direct_response(is_valid='true')

        logging.info("A direct verified gave data with signature %r but from data we expected %r :(", signature, expected_signature)
        return direct_response(is_valid='false')


app.add_url_rule('/server', view_func=ServerEndpoint.as_view('server'))


@app.route('/allow', methods=('POST',))
def allow():
    csrf_token = request.form['token']
    if b32decode(csrf_token) != session.get('csrf_token'):
        return indirect_response(orig_args, error="Someone forged the login form!!1!")

    # TODO: verify that the viewer is the site owner or w/e

    orig_args = dict(urlparse.parse_qsl(request.form['request_args']))
    if 'yes' not in request.form:
        return indirect_response(orig_args, mode='cancel')

    resp = {
        'ns': 'http://specs.openid.net/auth/2.0',
    }

    # Yay, assert the authentication.
    assoc_handle, mac_key = None, None
    try:
        assoc_handle = orig_args['openid.assoc_handle']
    except KeyError:
        pass  # make one up
    else:
        cur = g.db_conn.cursor()
        cur.execute("SELECT secret, assoc_type FROM openid_associations WHERE handle = %s AND private IS FALSE AND %s < expires",
            (assoc_handle, datetime.utcnow()))
        result = cur.fetchone()
        if result is None:
            resp['invalidate_handle'] = assoc_handle  # and make up a key
        else:
            mac_key, assoc_type = result
        cur.close()

    # If the handle was invalid or not given, make up a new private association for the relying party to directly verify against.
    if mac_key is None:
        assoc_type = 'HMAC-SHA256'
        mac_key = os.urandom(32)
        assoc_handle = b64encode(os.urandom(20))
        expires = datetime.utcnow() + timedelta(seconds=1000)

        cur = g.db_conn.cursor()
        cur.execute("INSERT INTO openid_associations (handle, private, secret, assoc_type, expires) VALUES (%s, true, %s, %s, %s)",
            (assoc_handle, bytearray(mac_key), assoc_type, expires))
        g.db_conn.commit()
        cur.close()

    # We don't really need to record the squib. We'd have to get the same six random bytes in the same second to duplicate one. It's up to the client to ensure uniqueness to prevent replay attacks.
    squib_now = datetime.utcnow().replace(microsecond=0).isoformat()
    squib_junk = b64encode(os.urandom(6))
    squib = '%sZ%s' % (squib_now, squib_junk)

    resp.update({
        'op_endpoint': url_for('.server', _external=True),
        'assoc_handle': assoc_handle,
        'response_nonce': squib,
        'claimed_id': orig_args['openid.claimed_id'],
        'identity': orig_args['openid.identity'],
        'return_to': orig_args['openid.return_to'],
    })
    resp_items = resp.items()

    signed_fields = ','.join(k for k, v in resp_items) + ',signed'
    resp['signed'] = signed_fields
    resp_items.append(('signed', signed_fields))  # eh just add it manually

    plaintext = kv(openid_prefix(resp_items))
    logging.debug("Signing plaintext %r", plaintext)
    digestmod = hashlib.sha1 if assoc_type == 'HMAC-SHA1' else hashlib.sha256
    signer = hmac.new(mac_key, plaintext, digestmod)
    signature = b64encode(signer.digest())

    # Don't include mode in the signature, since direct verifiers have to change the mode from 'id_res' to 'check_authentication' anyway so we can't check such a signature.
    resp['mode'] = 'id_res'
    resp['sig'] = signature
    return indirect_response(orig_args, **resp)


@app.route('/')
def hello_world():
    return u'Hello world!'


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    app.run(debug=True)
