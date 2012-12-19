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

3. Install the database table:

    python initdb.py

4. Customize a configuration file for your install:

    cp conf/flid.conf-example flid.conf
    vim flid.conf

5. All done! Run `flid.py` or set up the flid app to run as you run Python apps.

    FLID_SETTINGS=flid.conf python flid.py

See `conf/supervisor.conf-example` for an example of how to set up flid with [supervisor][] and [gunicorn][].

[a virtual environment]: http://pypi.python.org/pypi/virtualenv
[supervisor]: http://supervisord.org
[gunicorn]: http://gunicorn.org


## License ##

flid is available under the BSD license. See `LICENSE`.
