import functools
import hashlib
import OpenSSL.crypto
from datetime import datetime
from flask import send_file
import os
import struct

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.utils import secure_filename

import db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        error = None

        if not check_password(password):
            error = 'Invalid login.'

        if error is None:
            session.clear()
            session['user_id'] = username
            return redirect(url_for('auth.user'))

        flash(error)

    return render_template('auth/login.html')

ALLOWED_EXTENSIONS = {'p12'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@bp.route('/cert', methods=('GET', 'POST'))
def cert():
    if request.method == 'GET':
        session['challenge'] = random_challenge()
        return render_template('auth/cert.html', challenge=session['challenge'])
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename != '' and allowed_file(file.filename):
                response = request.form['challenge']
                #print(f"Answering to challenge {session['challenge']}")
                check_certificate(file.read(), response)
                #TODO: if ok -> login
                session['challenge'] = random_challenge() # New challenge at each reload
                return render_template('auth/cert.html', challenge=session['challenge'])
            else:
                flash("Invalid file format")
                return render_template('auth/cert.html', challenge=session['challenge'])
        else:
            flash('Please select a file...')
            return render_template('auth/cert.html', challenge=session['challenge'])
    return render_template('auth/cert.html', challenge=session['challenge'])

def check_certificate(bytestring, response):
    #TODO check response + certificate validity
    flash(f"Challenge Response {response}")

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        user_data = db.execute(f"SELECT uid,firstname,lastname,email FROM users WHERE uid = '{user_id}'")
        if user_data:
            user_data = user_data[0] # Remove the outside tuple
            # TODO use DB API for getting the data
            # get_user_data(username, cnx)
            user_dict = dict(username=user_data[0], firstname=user_data[1], lastname=user_data[2], email=user_data[3])
            g.user = user_dict

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


@bp.route('/update_info', methods=['POST'])
@login_required
def update_info():
    username = request.form['username']
    firstname = request.form['firstname']
    lastname = request.form['lastname']
    email = request.form['email']
    password = request.form['password']

    # TODO: change to use DB API to chang information
    return update_information(username, firstname, lastname, email, password)

@bp.route('/issue_cert', methods=['POST'])
@login_required
def issue_cert():
    password = request.form['password2']

    if check_password(password):
        # TODO send certificate issuing request to coreCA
        # And return real certificate instead of placeholder
        return send_file("cert/client.crt", as_attachment=True)
    else:
        flash("Invalid password...")
        return render_template('auth/user.html')

@bp.route('/revoke_cert', methods=['POST'])
@login_required
def revoke_cert():
    password = request.form['password3']

    if check_password(password):
        # TODO send revokation request to coreCA
        flash("Certificate revoked...")
    else:
        flash("Invalid password...")
    return render_template('auth/user.html')

@bp.route('/user', methods=['GET'])
@login_required
def user():
    certificate = get_user_certificate()
    return render_template('auth/user.html', certificate=certificate)

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))



def check_password(password):
    #TODO link up with Database API
    # check_password(username_password, cnx)
    return True

def update_information(username, firstname, lastname, email, password):
    db.init_prepare_statements() # determine why it doesn't work in the init hase sometimes...

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
        db.prepared_update(db.PREP_PASSWORD, password, session['user_id'])
        logout()
        flash("Password changed, please login again...")

    # If there were modifications, inform the user and refresh page        
    if firstname or lastname or email:
        flash("Information updated")
    return redirect(url_for('auth.user'))

def human_readable(date_bytes):
    return datetime.strptime(date_bytes.decode('ascii'), '%Y%m%d%H%M%SZ')

def get_user_certificate():
    #TODO: get real cert from coreCA

    # PLACEHOLDER CERTIFICATE
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, 
        open('cert/client.crt').read()
    )
    start_date = human_readable(cert.get_notBefore())
    end_date = human_readable(cert.get_notAfter())
    serial = str(cert.get_serial_number())#[-10:]
    sha1 = cert.digest("sha1").decode("utf-8")
    
    # The dict structure (notBefore, notAfterm serialNumber, fingerprint) is used in the html template, do not change!
    certificate = dict(notBefore=start_date, notAfter=end_date, serialNumber=serial, fingerprint=sha1)
    return certificate

def random_challenge():
    # Random int from os.urandom() -> crypto secure
    return struct.unpack('i', os.urandom(4))[0]