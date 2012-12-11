import os

from flask import Flask, g, make_response, render_template, request, session, url_for
from flask.views import MethodView
import openid
from openid.server.server import Server, ProtocolError
from openid.store.sqlstore import PostgreSQLStore
import psycopg2


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
    store = PostgreSQLStore(g.db_conn)
    g.server = Server(store, url_for('.server', _external=True))

@app.teardown_request
def teardown_request(exc):
    g.server = None
    g.db_conn.close()

def openid_to_flask_response(response):
    webr = g.server.encodeResponse(response)  # raises server.EncodingError
    resp = make_response(webr.body, webr.code)
    for header, value in webr.headers.iteritems():
        resp.headers[header] = value
    return resp


class ServerEndpoint(MethodView):

    def get(self):
        return self.server_endpoint(request.args)

    def post(self):
        return self.server_endpoint(request.form)

    def server_endpoint(self, query):
        try:
            openid_request = g.server.decodeRequest(query)
        except ProtocolError, exc:
            return openid_to_flask_response(exc)

        if openid_request is None:
            return render_template('about.html')

        if openid_request.mode in ('checkid_immediate', 'checkid_setup'):
            return self.checkid_response(openid_request)

        resp = g.server.handleRequest(openid_request)
        return openid_to_flask_response(resp)

    def checkid_response(self, openid_request):
        # TODO: let through previously trusted trust roots.
        # For now, no one is ever previously authorized.
        if request.immediate:
            return openid_to_flask_response(openid_request.answer(False))

        try:
            csrf_token = session['csrf_token']
        except KeyError:
            csrf_token = session['csrf_token'] = os.urandom(24)
        return render_template('decide.html', openid_request=openid_request, csrf_token=csrf_token)


app.add_url_rule('/server', view_func=ServerEndpoint.as_view('server'))


@app.route('/allow', methods=('POST',))
def allow():
    oir_args = dict(urlparse.parse_qsl(request.form['request_args']))
    openid_request = Message.fromPostArgs(oir_args)

    if 'yes' not in request.form:
        return openid_to_flask_response(openid_request.answer(False))

    if openid_request.idSelect():
        identity = url_for('.ident', _external=True)
    else:
        identity = openid_request.identity
    resp = openid_request.answer(True, identity)
    return openid_to_flask_response(resp)


@app.route('/')
def hello_world():
    return u'Hello world!'


if __name__ == '__main__':
    app.run(debug=True)
