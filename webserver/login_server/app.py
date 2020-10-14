import os

from flask import Flask
from flask_mysqldb import MySQL
from flask import jsonify

import db
import auth
import ssl_cert

app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
    SECRET_KEY='dev',
)

db.init_db(app)

# ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

@app.route('/')
def index():
    return "<a href='/auth/login'> go to login</a>"

@app.route('/test')
def test():
    cur = db.mysql.connection.cursor()
    cur.execute("SHOW SESSION STATUS")
    data = jsonify(data=cur.fetchall())
    cur.close()
    return data

@app.route('/database')
def database():
    #mysql = get_db()
    cur = db.mysql.connection.cursor()
    statement = "SELECT * FROM users"
    cur.execute(statement)
    #mysql.connection.commit()
    data = jsonify(data=cur.fetchall())
    cur.close()
    return data

app.register_blueprint(auth.bp)

if __name__ == "__main__":
    context = ssl_cert.setup()
    app.run(host='127.0.0.1', port='5000', ssl_context=context)

    