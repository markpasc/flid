# flid #

flid is a single-serving OpenID 2.0 server.

A short Flask app for Python 2.5, flid implements OpenID 2.0 itself with no third-party dependencies besides Flask and `psycopg2`.

Users are authenticated with a single password. flid will assert any specified identity for anyone with that password.


## Install ##

Consider installing flid in [a virtual environment][] to isolate it from the rest of the system.

1. Install flid's dependencies:

    pip install -r requirements.txt

2. Create a PostgreSQL database to use:

    createdb flid

3. Customize a configuration file for your install:

    cp conf/flid.conf-example flid.conf
    vim flid.conf

4. Install the database table:

    FLID_SETTINGS=flid.conf python flid.py --init

5. All done! Run `flid.py` or set up the flid app to run as you run Python apps.

    FLID_SETTINGS=flid.conf python flid.py

See `conf/supervisor.conf-example` for an example of how to set up flid with [supervisor][] and [gunicorn][].

[a virtual environment]: http://pypi.python.org/pypi/virtualenv
[supervisor]: http://supervisord.org
[gunicorn]: http://gunicorn.org


## How to use ##

To use the server, choose the page you want to use as your OpenID. In its `<head>`, set the `openid2.provider` link in that page to your flid site's `/server` URL. For example, if your web page were `example.com/alice/` and you set up flid to run on `id.example.com`, you would add the `<link>` tag shown here to your page:

    <head>
        <meta charset="utf-8">
        <title>Alice Example</title>
        <link rel="openid2.provider" href="http://id.example.com/server">
    </head>

Then, when prompted for your OpenID, enter `example.com/alice/`. The site will redirect you to flid where you can enter your password and sign into the site.


## Use HTTPS for security ##

For full security, set up your flid site to run on HTTPS.

Your password is protected from snooping network peers by being signed in the browser (see `templates/decide.html`). However, someone who controls the network can still impersonate your flid server (a man-in-the-middle attack) and serve you a different but identical-looking page that gives the attacker your password.

You can only be sure the server you're signing into is your flid server by contacting it only over HTTPS with a properly issued server-side certificate.


## License ##

flid is available under the BSD license. See `LICENSE`.
