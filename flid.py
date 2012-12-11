import os

from flask import Flask, make_response, render_template, request, url_for
from flask.views import MethodView
import openid
from openid.server.server import Server, ProtocolError
from openid.store.sqlstore import PostgreSQLStore
import psycopg2


class DefaultSettings(object):
    DEBUG = True

default_settings = DefaultSettings()


app = Flask(__name__)
app.config.from_object('flid.default_settings')
if 'FLID_SETTINGS' in os.environ:
    app.config.from_envvar('FLID_SETTINGS')


class OpenIDServer(MethodView):

    def __init__(self):
        conn = psycopg2.connect(database='flid')
        store = PostgreSQLStore(conn)
        self.server = Server(store, url_for('.server', _external=True))

    def get(self):
        return self.server_endpoint(request.args)

    def post(self):
        return self.server_endpoint(request.form)

    def server_endpoint(self, query):
        try:
            request = self.server.decodeRequest(query)
        except ProtocolError, exc:
            return self.openid_response(exc)

        if request is None:
            return render_template('about.html')

    def openid_response(self, response):
        webr = self.server.encodeResponse(response)  # raises server.EncodingError
        resp = make_response(webr.body, webr.code)
        for header, value in webr.headers.iteritems():
            resp.headers[header] = value
        return resp


app.add_url_rule('/server', view_func=OpenIDServer.as_view('server'))


@app.route('/')
def hello_world():
    return u'Hello world!'


if __name__ == '__main__':
    app.run(debug=True)
