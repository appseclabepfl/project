import functools
import hashlib
from  OpenSSL import crypto
from datetime import datetime
from flask import send_file
import os
import struct
import base64
import db_API

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.utils import secure_filename

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        error = None

        if True:
#        if not db_API.check_password(username, password, context):
            error = 'Invalid login.'

        if error is None:
            session.clear()
            session['user_id'] = username
            return redirect(url_for('auth.user'))

        flash(error)
    return render_template('auth/login.html')

@bp.route('/cert', methods=('GET', 'POST'))
def cert():
    if request.method == 'GET':
        session['challenge'] = random_challenge()
        return render_template('auth/cert.html', challenge=session['challenge'])
    elif request.method == 'POST':
        response = request.form['challenge']
        cert = request.form['certificate']

        if check_certificate(cert, response):
            return redirect(url_for('auth.user'))
        else:
            session['challenge'] = random_challenge() # New challenge at each reload
            flash("Invalid certificate")
            return render_template('auth/cert.html', challenge=session['challenge'])

@bp.route('/admin', methods=('GET', 'POST'))
def admin():
    if request.method == 'GET':
        session['challenge'] = random_challenge()
        return render_template('auth/admin.html', challenge=session['challenge'])
    elif request.method == 'POST':
        response = request.form['challenge']
        cert = request.form['certificate']

        # TODO: check if admin user (admin folder)
        if check_certificate(cert, response):
            session["admin"] = True
            return redirect(url_for('auth.stats'))
        else:
            session['challenge'] = random_challenge() # New challenge at each reload
            flash("Invalid certificate")
            return render_template('auth/admin.html', challenge=session['challenge'])

def extract_uid(cert):
    for name, value in cert.get_subject().get_components():
        if name.decode("utf-8") == "UID":
            return value.decode("utf-8")
    return "UNKNOWN_USER"

def check_certificate(certB64, responseB64):
    #TODO Check if cert in CRL (+ notBefore and notAfter dates?) 

    cert_bytes = base64.b64decode(certB64.encode("utf-8"))
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bytes)
    signature = base64.b64decode(responseB64.encode("utf-8"))

    try:
        crypto.verify(cert, signature, str(session["challenge"]), "sha256")
    except crypto.Error: # invalid signature
        return False
    
    # Set user_id for the login session
    session.clear()
    session['user_id'] = extract_uid(cert)
    return True

@bp.before_app_request
def on_page_load():
    is_admin = session.get('admin')
    user_id = session.get('user_id')
    g.user = None
    permanent_db_context()
    load_logged_in_user_data(user_id)
    set_admin_permissions(is_admin)
    check_phone_user_agent(request.user_agent.string)

def permanent_db_context():
    if not hasattr(g, 'db_context'):
        g.db_context = db_API.init()

def check_phone_user_agent(user_agent):
    if "Android" in user_agent or "iPhone" in user_agent or "Phone" in user_agent:
        set_responsive_design()
    else:
        set_normal_design()

def set_responsive_design():
    session["phone"] = True
    g.admin = True

def set_normal_design():
    session["phone"] = False

def load_logged_in_user_data(user_id):
    if user_id is None:
        g.user = None
    else:
        user_data = db_API.get_user_data(user_id, g.db_context)
        #user_data = dict(uid="username_placeholder", firstname="firstname_placeholder", lastname="lastname_placeholder", email="email_placeholder")
        if user_data is not None: #if uid not in DB
            g.user = user_data

def set_admin_permissions(is_admin):
    if is_admin is None:
        g.admin = False
    else:
        g.admin = True


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            session.clear()
            flash("Not logged in...")
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not g.admin:
            session.clear()
            flash("Not an admin...")
            return redirect(url_for('auth.admin'))
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

    return update_information(username, firstname, lastname, email, password)

@bp.route('/issue_cert', methods=['POST'])
@login_required
def issue_cert():
    password = request.form['password2']

    if check_password(password):
        # TODO send certificate issuing request to coreCA
        # + revoke current certificate if there is one
        # And return real certificate instead of placeholder
        return send_file("cert/server.crt", as_attachment=True)
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

@bp.route('/stats', methods=['GET'])
@admin_required
def stats():
    # TODO: get real stats from core_CA
    stats = dict(issued=0, revoked=0, serialNumber=0)
    return render_template('auth/stats.html', ca_info=stats)

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

def update_information(uid, firstname, lastname, email, password):
    new_data = {}

    if uid:
        new_data['uid'] = uid
        print(f"new uid {uid}")
        session['user_id'] = uid
    else:
        new_data['uid'] = session['user_id'] 
    if firstname:
        new_data['firstname'] = firstname
        print(f"new firstname {firstname}")
    else:
        new_data['firstname'] = g.user['firstname']
    if lastname:
        new_data['lastname'] = lastname
        print(f"new lastname {lastname}")
    else:
        new_data['lastname'] = g.user['lastname']
    if email:
        new_data['email'] = email
        print(f"new email {email}")
    else:
        new_data['email'] = g.user['email']
    if password:
        new_data['pwd'] = password
        logout()
        flash("Password changed, please login again...")
    else:
        new_data['pwd'] = ""

    # Update in DB
    db_API.update_user_data(new_data, g.db_context)

    if firstname or lastname or email:
        flash("Information updated")

    return redirect(url_for('auth.user'))

def human_readable(date_bytes):
    return datetime.strptime(date_bytes.decode('ascii'), '%Y%m%d%H%M%SZ')

def get_user_certificate():
    #TODO: get real cert from coreCA

    # PLACEHOLDER CERTIFICATE
    cert = crypto.load_certificate(
        crypto.FILETYPE_PEM, 
        open('cert/rootCA.crt').read()
    )
    start_date = human_readable(cert.get_notBefore())
    end_date = human_readable(cert.get_notAfter())
    serial = str(cert.get_serial_number())
    sha1 = cert.digest("sha1").decode("utf-8")
    
    # The dict structure (notBefore, notAfterm serialNumber, fingerprint) is used in the html template, do not change!
    certificate = dict(notBefore=start_date, notAfter=end_date, serialNumber=serial, fingerprint=sha1)
    return certificate

def random_challenge():
    # Random int from os.urandom() -> crypto secure
    return struct.unpack('i', os.urandom(4))[0]
