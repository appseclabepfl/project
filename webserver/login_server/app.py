import os

from flask import Flask
from flask_mysqldb import MySQL
from flask import jsonify

import auth
import ssl_cert

app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
    SECRET_KEY='dev',
    MAX_CONTENT_LENGTH=5*1024, #max file size for upload 5 kB
)

# ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

@app.route('/')
def index():
    return "<a href='/auth/login'> go to login</a>"

app.register_blueprint(auth.bp)

if __name__ == "__main__":
    context = ssl_cert.setup()
    app.run(host='127.0.0.1', port='5000', ssl_context=context)

    