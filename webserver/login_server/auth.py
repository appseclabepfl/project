import functools
import hashlib
import OpenSSL.crypto 

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from login_server.db import *

bp = Blueprint('auth', __name__, url_prefix='/auth')

# https://flask.palletsprojects.com/en/1.1.x/tutorial/views/

def check_password(password, hashedpwd):
    sha1 = hashlib.sha1()
    sha1.update(password)
    return sha1.hexdigest() == hashedpwd

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        error = None
        pwd = execute(f"SELECT pwd FROM users WHERE uid = '{username}'")

        if not pwd or not check_password(password, pwd[0][0]):
            error = 'Invalid login.'

        if error is None:
            session.clear()
            session['user_id'] = username
            return redirect(url_for('auth.user'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        user_data = execute(f"SELECT firstname,lastname,email FROM users WHERE uid = '{user_id}'")
        if user_data:
            user_data = user_data[0] # Remove the outside tuple
            user_dict = dict(firstname=user_data[0], lastname=user_data[1], email=user_data[2])
            g.user = user_dict

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

@bp.route('/user', methods=('GET', 'POST'))
@login_required
def user():
    #cert = OpenSSL.crypto.load_certificate(
    #    OpenSSL.crypto.FILETYPE_PEM, 
    #    open('login_server/certificates/DigiCertBaltimoreCA-2G2.crt').read()
    #)
    #print(cert.get_signature_algorithm())
    # get_notBefore()
    # get_notAfter()
    # get_serial_number()
    # get_signature_algorithm()
    # sh1 fingerprint?

    init_prepare_statements() # TODO determine why it doesn't work in the init hase sometimes...

    if request.method == 'POST':
        # Get input from forms
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']

        # If non-empty -> write new info to database
        if firstname:
            prepared_update(PREP_FIRSTNAME, firstname, session['user_id'])
        if lastname:
            prepared_update(PREP_LASTNAME, lastname, session['user_id'])
        if email:
            prepared_update(PREP_EMAIL, email, session['user_id'])

        # If there were modifications, inform the user and refresh page        
        if firstname or lastname or email:
            flash("Information updated")
        return redirect(url_for('auth.user'))
    return render_template('auth/user.html')

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))



