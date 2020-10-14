from flask_mysqldb import MySQL
from flask import current_app, g
from flask.cli import with_appcontext


# Constants
PREP_USERNAME = "username_query"
PREP_FIRSTNAME = "firstname_query"
PREP_LASTNAME = "lastname_query"
PREP_EMAIL = "email_query"
PREP_PASSWORD = "password_query"
mysql = MySQL()

def init_db(app):
    app.config['MYSQL_HOST'] = 'localhost'
    app.config['MYSQL_USER'] = 'root'
    app.config['MYSQL_PASSWORD'] = 'H233Hmysql'
    app.config['MYSQL_DB'] = 'imovies'
    mysql.init_app(app)
    with app.app_context():
        init_prepare_statements()
    
    
# Prepared statements initation and execution
# https://dev.mysql.com/doc/refman/8.0/en/sql-prepared-statements.html
def init_prepare_statements():
    cur = mysql.connection.cursor()
    cur.execute(f"PREPARE {PREP_USERNAME} FROM 'UPDATE users SET uid=? WHERE uid=?';")
    cur.execute(f"PREPARE {PREP_FIRSTNAME} FROM 'UPDATE users SET firstname=? WHERE uid=?';")
    cur.execute(f"PREPARE {PREP_LASTNAME} FROM 'UPDATE users SET lastname=? WHERE uid=?';")
    cur.execute(f"PREPARE {PREP_EMAIL} FROM 'UPDATE users SET email=? WHERE uid=?';")
    cur.execute(f"PREPARE {PREP_PASSWORD} FROM 'UPDATE users SET pwd=? WHERE uid=?';")
    #mysql.connection.commit()
    cur.close()

def prepared_update(attribute, new_attribute, uid):
    cur = mysql.connection.cursor()
    cur.execute(f"SET @new='{new_attribute}'")
    cur.execute(f"SET @uid='{uid}'")
    cur.execute(f"EXECUTE {attribute} USING @new,@uid;")
    cur.close()

# Basic execute
def execute(query):
    cur = mysql.connection.cursor()
    cur.execute(query)
    data = cur.fetchall()
    cur.close()
    return data