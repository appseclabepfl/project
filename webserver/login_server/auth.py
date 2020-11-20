import functools
import hashlib
from  OpenSSL import crypto
from datetime import datetime
import os
import struct
import base64
import db_API
import CA_API
from json.decoder import JSONDecodeError
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from flask import (Blueprint, flash, g, redirect, render_template, request, session, url_for, send_file)

bp = Blueprint('auth', __name__, url_prefix='/auth')

USER_CERT_FOLDER = "cert/users/"
ADMIN_CERT_PATH = "cert/admin/admin.pem"

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username'].encode('utf-8')
        password = request.form['password'].encode('utf-8')

        error = None

        if not db_API.check_password(username, password, g.db_context):
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

        if check_admin_certificate(cert, response):
            session["admin"] = True
            return redirect(url_for('auth.stats'))
        else:
            session['challenge'] = random_challenge() # New challenge at each reload
            flash("Invalid certificate")
            return render_template('auth/admin.html', challenge=session['challenge'])

def extract_uid(cert):
    for name, value in cert.get_subject().get_components():
        if name.decode("utf-8") == "UID":
            return value
    return "UNKNOWN_USER".encode('utf-8')

def is_revoked_in_crl(certificate):
    f = open(CA_API.CRL_PATH)
    crl = crypto.load_crl(crypto.FILETYPE_PEM, f.read())
    f.close()

    revokations = crl.get_revoked()
    for revok in revokations:
        revok_serial = int(revok.get_serial().decode('ASCII'), 16) #It is a hex nb encoded in ASCII
        cert_serial = certificate.get_serial_number() #It is an int
        if revok_serial == cert_serial:
            return True
    return False

def check_admin_certificate(certB64, responseB64):
    valid = check_certificate(certB64, responseB64)

    cert_bytes = base64.b64decode(certB64.encode("utf-8"))
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bytes)
    if not os.path.exists(ADMIN_CERT_PATH):
        return False
    admin_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ADMIN_CERT_PATH).read())
    return admin_cert.get_serial_number() == cert.get_serial_number()

def check_certificate(certB64, responseB64):
    cert_bytes = base64.b64decode(certB64.encode("utf-8"))
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bytes)

     # Check signature is valid
    signature = base64.b64decode(responseB64.encode("utf-8"))

    try:
        crypto.verify(cert, signature, str(session["challenge"]), "sha256")
    except crypto.Error: # invalid signature
        return False

    # Check CRL
    if is_revoked_in_crl(cert):
        return False

    # Check that cert comes from CA
    if not CA_API.verify_certificate(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)):
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
        try:
            user_data = db_API.get_user_data(user_id, g.db_context)
        except JSONDecodeError:
            user_data = None
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
    username = session['user_id']
    password = request.form['password2'].encode('utf-8')

    if db_API.check_password(username, password, g.db_context):
        new_cert = f"{USER_CERT_FOLDER}{username.decode('utf-8')}.p12"
        if not CA_API.getNewCert(new_cert, username.decode('utf-8')):
            download = send_file(new_cert, as_attachment=True) # No problem -> download new cert
            replacePKCSwithCert(new_cert)
            return download
        else: # -> problem revoke anyway and retry
            error = CA_API.revokeCert(username.decode('utf-8'))
            deleteLocalFiles(username.decode('utf-8'))
            error = error or CA_API.getNewCert(new_cert, username.decode('utf-8'))
            if not error:
                download = send_file(new_cert, as_attachment=True)
                replacePKCSwithCert(new_cert)
                return download
            else:
                flash("Failed to issue a new certificate")
    else:
        flash("Invalid password...")
        return render_template('auth/user.html')

def replacePKCSwithCert(filepath):
    new_file = filepath.replace(".p12", ".pem")
    if os.path.exists(filepath):
        # Save certificate to disk
        p12 = crypto.load_pkcs12(open(filepath, 'rb').read())
        cert = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
        with open(new_file, 'wb') as f:
            f.write(cert)
        # Remove PKCS#12 from disk
        os.remove(filepath)

def deleteLocalFiles(uid):
    filepath = f"{USER_CERT_FOLDER}{uid}.pem"
    if os.path.exists(filepath):
        os.remove(filepath)
    filepath = filepath.replace(".pem",".p12")
    if os.path.exists(filepath):
        os.remove(filepath)

@bp.route('/revoke_cert', methods=['POST'])
@login_required
def revoke_cert():
    username = session['user_id']
    password = request.form['password3'].encode('utf-8')

    if db_API.check_password(username, password, g.db_context):
        if CA_API.revokeCert(username.decode('utf-8')):
            flash("Revokation failed")
        else:
            deleteLocalFiles(username.decode('utf-8'))
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
    raw_stats = CA_API.getCAStats()
    splitted = raw_stats.split(",")
    print(splitted)
    stat_issued = splitted[0].replace("ISSUED CERTS: ", "")
    stat_revoked = splitted[1].replace("REVOKED CERTS: ", "")
    stat_serial = splitted[2].replace("SERIAL NUMBER: ", "")
    stats = dict(issued=stat_issued, revoked=stat_revoked, serialNumber=stat_serial)
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
        new_data['uid'] = session['user_id'].decode('utf-8') 
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
    username = session['user_id'].decode('utf-8')
    filepath = f"{USER_CERT_FOLDER}{username}.pem"

    if os.path.exists(filepath):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(filepath).read())
        start_date = human_readable(cert.get_notBefore())
        end_date = human_readable(cert.get_notAfter())
        serial = str(cert.get_serial_number())
        sha1 = cert.digest("sha1").decode("utf-8")
        # The dict structure (notBefore, notAfterm serialNumber, fingerprint) is used in the html template, do not change!
        return dict(notBefore=start_date, notAfter=end_date, serialNumber=serial, fingerprint=sha1)
    else:
        return None

def random_challenge():
    # Random int from os.urandom() -> crypto secure
    return struct.unpack('i', os.urandom(4))[0]
