import os

from flask import Flask
from flask_mysqldb import MySQL
from flask import jsonify

from login_server.db import *

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
    )


    init_db(app)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route('/')
    def hello():
        return 'Hello, World!'

    @app.route('/test')
    def test():
        cur = mysql.connection.cursor()
        cur.execute("SHOW SESSION STATUS")
        data = jsonify(data=cur.fetchall())
        cur.close()
        return data

    @app.route('/database')
    def database():
        #mysql = get_db()
        cur = mysql.connection.cursor()
        statement = "SELECT * FROM users"
        cur.execute(statement)
        #mysql.connection.commit()
        data = jsonify(data=cur.fetchall())
        cur.close()
        return data

    from . import auth
    app.register_blueprint(auth.bp)
    return app

    