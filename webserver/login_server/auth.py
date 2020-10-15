import functools
import hashlib
import OpenSSL.crypto
import datetime

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.utils import secure_filename

import db

bp = Blueprint('auth', __name__, url_prefix='/auth')

def hash_password(password):
    sha1 = hashlib.sha1()
    sha1.update(password)
    return sha1.hexdigest()

def check_password(password, hashedpwd):
    return hash_password(password) == hashedpwd

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        error = None
        pwd = db.execute(f"SELECT pwd FROM users WHERE uid = '{username}'")

        if not pwd or not check_password(password, pwd[0][0]):
            error = 'Invalid login.'

        if error is None:
            session.clear()
            session['user_id'] = username
            return redirect(url_for('auth.user'))

        flash(error)

    return render_template('auth/login.html')

ALLOWED_EXTENSIONS = {'crt'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@bp.route('/cert', methods=('GET', 'POST'))
def cert():
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                flash('Enter a certificate manually or select a file...')
                return redirect(request.url)
            if file and allowed_file(file.filename):
                check_certificate(file.read())
                return redirect(request.url)
            else:
                flash("Invalid file")
                return redirect(request.url)
        elif request.form['cert']:
            #flash("Manual copy/paste")
            check_certificate(bytes(request.form['cert'], 'utf-8'))
        else:
            flash('Enter a certificate manually or select a file...')
            return redirect(request.url)
    return render_template('auth/cert.html')

def check_certificate(bytestring):
    #TODO
    flash(f"Invalid certificate:\n{bytestring}")

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        user_data = db.execute(f"SELECT uid,firstname,lastname,email FROM users WHERE uid = '{user_id}'")
        if user_data:
            user_data = user_data[0] # Remove the outside tuple
            user_dict = dict(username=user_data[0], firstname=user_data[1], lastname=user_data[2], email=user_data[3])
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
    # PLACHOLDER CERTIFICATE
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, 
        open('cert/client.crt').read()
    )

    cert2 = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, 
        open('cert/server.crt').read()
    )
    #print(cert.get_signature_algorithm())
    # get_notBefore()
    # get_notAfter()
    # get_serial_number()
    # get_signature_algorithm()
    # sh1 fingerprint?
    certificates = []

    #ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z' #https://stackoverflow.com/questions/45810069/how-to-fetch-the-ssl-certificate-value-whether-its-expired-or-not/52298575
    #flash(datetime.datetime.strptime(str(cert.get_notAfter()), ssl_date_fmt))

    placeholder = dict(notBefore=cert.get_notBefore(), notAfter=cert.get_notAfter(), serialNumber=str(cert.get_serial_number())[-10:], algorithm=cert.get_signature_algorithm())
    placeholder2 = dict(notBefore=cert2.get_notBefore(), notAfter=cert2.get_notAfter(), serialNumber=str(cert2.get_serial_number())[-10:], algorithm=cert2.get_signature_algorithm())
    certificates.append(placeholder)
    certificates.append(placeholder2)

    db.init_prepare_statements() # TODO determine why it doesn't work in the init hase sometimes...

    if request.method == 'POST':
        # Get input from forms
        username = request.form['username']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password = request.form['password'].encode('utf-8') # TODO: compute the hash client side? (hash + salt?)

        # If non-empty -> write new info to database
        if username:
            db.prepared_update(db.PREP_USERNAME, username, session['user_id'])
            session['user_id'] = username
        if firstname:
            db.prepared_update(db.PREP_FIRSTNAME, firstname, session['user_id'])
        if lastname:
            db.prepared_update(db.PREP_LASTNAME, lastname, session['user_id'])
        if email:
            db.prepared_update(db.PREP_EMAIL, email, session['user_id'])
        if password:
            db.prepared_update(db.PREP_PASSWORD, hash_password(password), session['user_id'])
            logout()
            flash("Password changed, please login again...")

        # If there were modifications, inform the user and refresh page        
        if firstname or lastname or email:
            flash("Information updated")
        return redirect(url_for('auth.user'))
    return render_template('auth/user.html', certificates=certificates)

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))



