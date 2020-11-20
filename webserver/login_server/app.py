import os

from flask import Flask
from flask import jsonify
import logging

import auth
import ssl_cert

app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
    SECRET_KEY='dev',
)

# ensure the instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Save logs to file
logger = logging.getLogger('werkzeug')
handler = logging.FileHandler('webserver.log')
logger.addHandler(handler)
app.logger.addHandler(handler)

@app.route('/')
def index():
    return "<a href='/auth/login'> go to login</a>"

app.register_blueprint(auth.bp)

if __name__ == "__main__":
    context = ssl_cert.setup()
    app.run(host='10.10.20.2', port='5000', ssl_context=context)

    
