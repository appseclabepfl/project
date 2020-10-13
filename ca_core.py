import os
import glob
import datetime

from os import listdir
from os.path import isfile, join

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from OpenSSL.crypto import *

CERTIFICATES_PATH = "certificates/"
if not os.path.exists(CERTIFICATES_PATH):
    os.makedirs(CERTIFICATES_PATH)

ISSUED_PATH = "certificates/issued/"
if not os.path.exists(ISSUED_PATH):
    os.makedirs(ISSUED_PATH)

REVOKED_PATH = "certificates/revoked/"
if not os.path.exists(REVOKED_PATH):
    os.makedirs(REVOKED_PATH)

KEYS_PATH = "keys/"
if not os.path.exists(KEYS_PATH):
    os.makedirs(KEYS_PATH)

ROOT_CERTIFICATE_PATH = CERTIFICATES_PATH + 'root_certificate.pem'


def generate_rsa_private_key(public_exponent=65537, key_size=2048):
    """
    Generate rsa private key from public attributes

    Parameters
    ----------
    public_exponent: int
        public exponent of the RSA algorithm

    key_size: int
        size of the RSA private key

    Returns
    -------
    RSAPrivateKey
        the corresponding RSA private key

    """
    return rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size, backend=default_backend())


def get_user_attributes_dummy(user_id):
    """
    Returns database attributes for a user id

    Parameters
    ----------
    user_id: str
        User identifier

    Returns
    -------
    Tuple(user_first_name, user_last_name, user_email)
        user_first_name: str
            User first name
        user_last_name: str
            User last name
        user_email: str
            User email

    """
    # MySQL prepared statement
    # sql_command = ('SELECT lastname, firstname, email FROM users WHERE uid = %s')
    # cursor.execute(sql_command, (uid,))
    return "Tairieur", "Alain", "alaintairieur@gmail.com"


def pem_to_crl(crl_pem):
    """
    Transform a crl in the PEM format into a crl

    Parameters
    ----------
    crl_pem: pem
        pem crl to transform

    Returns
    -------
    CRL

    """
    return x509.load_pem_x509_crl(crl_pem, backend=default_backend())


def pem_to_certificate(certificate_pem):
    """
    Transform a certificate in the PEM format into a Certificate

    Parameters
    ----------
    certificate_pem: pem
        certificate to transform

    Returns
    -------
    Certificate

    """
    return x509.load_pem_x509_certificate(certificate_pem, default_backend())


def to_pem(c):
    """
    Transform a certificate or a CRL in the pem format

    Parameters
    ----------
    c: Certificate or CRL
        The correponding object to transform

    Returns
    -------
    pem
        certificate or a CRL in the pem format

    """
    return c.public_bytes(encoding=serialization.Encoding.PEM)


def get_certificate_attribute_value(certificate, oid):
    """
    Extracts the value of a certificate attribute

    Parameters
    ----------
    certificate: Certificate
        The correponding certificate

    oid: NameOID
        the corresponding attribute name

    Returns
    -------
    str
        The value of the certificate attribute

    """
    return certificate.subject.get_attributes_for_oid(oid)[0].value


def get_certificate_user_id(certificate):
    """
    Extracts certificate user id

    Parameters
    ----------
    certificate: Certificate
        The correponding certificate

    Returns
    -------
    str
        The value of the certificate user id

    """
    return get_certificate_attribute_value(certificate, NameOID.USER_ID)

def get_certificate_by_user_id(uid):
    """
    Return the certificate of the user corresponding with the uid

    Parameters
    ----------
    uid: str
        The uid

    Returns
    -------
    Certificate
        The certificate corresponding to the uid or None if there is no match or the certificate is already revoked

    """
    crl = CRL()

    #take all valid certificates that have the uid in their name
    certs = [f for f in listdir(ISSUED_PATH) if (isfile(join(ISSUED_PATH, f)) and f.endswith('.pem') and (uid in f))]
    valid_cert = [c for c in certs if (not is_revoked(c,crl=crl))]

    if len(valid_cert) > 0:
        return valid_cert[0]

    return None

def get_key_name(key):
    """
    Key name in filesystem

    Parameters
    ----------

    key: Key
        the corresponding key

    Returns
    -------
    str
        the name of the key

    """
    return 

def get_certificate_name(certificate):
    """
    Certificate name for the file system

    Parameters
    ----------

    certificate: Certificate
        the corresponding certificate

    Returns
    -------
    str
        the name of the certificate

    """
    return f"{get_certificate_user_id(certificate)}_{certificate.serial_number}.pem"


def write_certificate(certificate, certificate_file_name):
    """
    Write a certificate in the pem format

    Parameters
    ----------
    certificate: Certificate
        certificate to write

    certificate_file_name: str
        file to write the certificate

    Returns
    -------
    None

    """
    with open(certificate_file_name, 'w') as file:
        file.write(
            to_pem(certificate).decode())


def write_crl(crl, crl_file_name="crl.pem"):
    """
    Write a CRL in the pem format

    Parameters
    ----------
    crl: CRL
        certificate revocation list

    crl_file_name: str
        file to store the crl

    Returns
    -------
    None

    """
    write_certificate(crl, crl_file_name)


def read_file(file_name):
    """
    Read file

    Parameters
    ----------
    file_name: str
        name of the file

    Returns
    -------
    str
        the content of the file

    """
    with open(file_name, "rb") as file:
        return file.read()


def read_certificate(certificate_file_name):
    """
    Read a certificate

    Parameters
    ----------
    certificate_file_name: str
        file to read the certificate

    Returns
    -------
    Certificate
        the read certificate

    """
    pem_cert = read_file(certificate_file_name)

    return pem_to_certificate(pem_cert)


def read_crl(crl_file_name="crl.pem"):
    """
    Read a CRL

    Parameters
    ----------

    crl_file_name: str
        file to read the CRL

    Returns
    -------
    CRL
        the read CRL

    """
    crl_pem = read_file(crl_file_name)

    return pem_to_crl(crl_pem)


def save_key(key, filename):
    """
    Save a private key in the pem format

    Parameters
    ----------
    key: RSAPrivateKey
        the key to write

    filename: str
        file to write the key

    Returns
    -------
    None

    """
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(KEYS_PATH + filename, 'wb') as pem_out:
        pem_out.write(pem)


def load_key(filename):
    """
    Read a private key

    Parameters
    ----------
    filename: str
        file to read the key

    Returns
    -------
    RSAPrivateKey
        the read key

    """
    with open(KEYS_PATH + filename, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    return private_key


def create_root_certificate(root_certificate_file=None, root_private_key_file=None):
    """
    Create self signed root certificate

    Parameters
    ----------
    root_certificate_file: str
        file to store the root certificate

    root_private_key_file: str
        file to store the private key

    Returns
    -------
    Tuple(root_certificate, root_key)

        root_certificate: Certificate
            the root certificate

        root_key: RSAPrivateKey
            the root key

    """
    root_key = generate_rsa_private_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMoviesCA"),
    ])

    root_certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).sign(root_key, hashes.SHA256(), default_backend())

    if root_certificate_file:
        write_certificate(root_certificate, CERTIFICATES_PATH + root_certificate_file)

    if root_private_key_file:
        save_key(root_key, root_private_key_file)

    return root_certificate, root_key


def certificate_issuing(user_id, root_certificate_file=ROOT_CERTIFICATE_PATH,
                        root_private_key_file="root_private_key.pem", validity=30):
    """
    Create new certificate signed form the CA

    Parameters
    ----------

    user_id: str
        identifier of the user

    root_certificate_file: str
        file to store the root certificate

    root_private_key_file: str
        file to store the private key

    validity: int
        validity of the certificate in days

    Returns
    -------
    Tuple(root_certificate, root_key)

        certificate: Certificate
            the corresponding certificate

        root_key: RSAPrivateKey
            the private key of the new certificate

    """

    # Connect to the database and check user_id, user_pwd_hash

    root_certificate = read_certificate(root_certificate_file)

    user_last_name, user_first_name, user_email = get_user_attributes_dummy(user_id)

    certificate_key = generate_rsa_private_key()

    root_key = load_key(root_private_key_file)

    certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"iMovies"),
        x509.NameAttribute(NameOID.USER_ID, u"{}".format(user_id)),
        x509.NameAttribute(NameOID.SURNAME, u"{}".format(user_last_name)),
        x509.NameAttribute(NameOID.GIVEN_NAME, u"{}".format(user_first_name)),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"{}".format(user_email)),
    ])).issuer_name(
        root_certificate.issuer
    ).public_key(
        certificate_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity)
    ).sign(root_key, hashes.SHA256(), default_backend())

    write_certificate(certificate, ISSUED_PATH + get_certificate_name(certificate))
    save_key(certificate_key, user_id + '.pem')

    return certificate, certificate_key


def verify_certificate(certificate, root_certificate):
    """
    Verify if a certificate is valid (signed by a trusted CA)

    Parameters
    ----------

    certificate: Certificate
        certificate to verify

    root_certificate: Certificate
        root certificate (which must have signed the certificate)

    Returns
    -------
    bool

    """
    try:
        # verify raises ~cryptography.exceptions.InvalidSignature exception if the signature fails to verify.
        root_certificate.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            # Depends on the algorithm used to create the certificate
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        return True

    except InvalidSignature:

        return False


def create_pkcs12_bytes(cert_path, key_path):
    """
    Create p12 file (PKCS12 format) from pem files
    Use after issuing new certificate.

    Parameters
    ----------
    cert_path: str
        Path to newly generated certificate

    key_path: str
        Path to newly generated key

    Returns: bytes
    -------
    certificate and private key in PKCS12 format

    """
    pkcs12 = PKCS12()

    with open(cert_path, "r") as cert_file:
    
        cert = load_certificate(FILETYPE_PEM, cert_file.read())
        pkcs12.set_certificate(cert)

    with open(key_path, "r") as key_file:

        key = load_privatekey(FILETYPE_PEM,key_file.read())
        pkcs12.set_privatekey(key)
    
    return pkcs12.export()


def revoke_certificate(certificate):
    """
    Revoke a certificate

    Parameters
    ----------
    certificate: Certificate
        certificate to revoke

    Returns
    -------
    RevokedCertificate

    """
    builder = x509.RevokedCertificateBuilder()
    builder = builder.revocation_date(datetime.datetime.today())
    builder = builder.serial_number(certificate.serial_number)
    return builder.build(default_backend())


def create_revocation_list(folder):
    """
    Create a revocation list based on the pem files of a folder

    Parameters
    ----------

    folder: str
        Path of the folder containing the pem files

    Returns
    -------
    Revoked_Certificates[]
        List of revoked certificates

    """
    certificates = glob.glob(f'{folder}*.pem')
    return [revoke_certificate(read_certificate(certificate)) for certificate in certificates]


class CRL:
    """
    Updatable certificate revocation list (CRL)
    """

    def __init__(self, root_certificate_file=ROOT_CERTIFICATE_PATH, root_private_key_file="root_private_key.pem"):
        """
        self.revoked_certificates: List[RevokedCertificate]
            List of all the revoked certificates

        self.root_certificate_file: str
            file to store the root certificate

        self.root_private_key_file: str
            file to store the private key
        """
        self.revoked_certificates = create_revocation_list(REVOKED_PATH)
        self.root_certificate_file = root_certificate_file
        self.root_private_key_file = root_private_key_file

    def get_crl(self):
        """
        Creates a new CRL in the pem format

        Parameters
        ----------
        Returns
        -------
        CRL in the pem format

        """
        # Load our root cert
        root_key = load_key(self.root_private_key_file)

        root_certificate = read_certificate(self.root_certificate_file)

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.last_update(datetime.datetime.today())
        builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(1, 0, 0))
        builder = builder.issuer_name(root_certificate.issuer)
        if self.revoked_certificates:
            for revoked_cert in self.revoked_certificates:
                builder = builder.add_revoked_certificate(revoked_cert)
        cert_revocation_list = builder.sign(
            private_key=root_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

        return cert_revocation_list, cert_revocation_list.public_bytes(encoding=serialization.Encoding.PEM)

    def update_crl(self, certificate):
        """
        Update the current CRL

        Parameters
        ----------
        certificate: Certificate
            certificate to add

        Returns
        -------
        updated CRL in the pem format

        """
        write_certificate(certificate, REVOKED_PATH + get_certificate_name(certificate))
        self.revoked_certificates.append(revoke_certificate(certificate))
        crl, crl_pem = self.get_crl()
        write_crl(crl, CERTIFICATES_PATH + "crl.pem")
        return crl, crl_pem


def is_revoked(certificate, crl_pem=None, crl_path="", crl=None):
    """
    Check if a certificate is revoked in a particular CRL

    Parameters
    ----------
    certificate: Certificate
        certifficate to check

    crl_pem: Byte[]
        the correponding CRL in the pem format

    crl_path: str
        Path of the CRL if crl_pem is None

    crl: CRL
        A CRL object

    Returns
    -------
    bool

    """
    if not crl:

        if crl_pem:
            crl = pem_to_crl(crl_pem)  # x509.load_pem_x509_crl(crl_pem, backend=default_backend())
        else:
            crl = read_crl(crl_path)
    
    return crl.get_revoked_certificate_by_serial_number(certificate.serial_number) != None
