import os
import datetime

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

CERTIFICATES_PATH = "certificates/"
if not os.path.exists(CERTIFICATES_PATH):
    os.makedirs(CERTIFICATES_PATH)

KEYS_PATH = "keys/"
if not os.path.exists(KEYS_PATH):
    os.makedirs(KEYS_PATH)


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
    user_id
    return "Tairieur", "Alain", "alaintairieur@gmail.com"


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
    with open(CERTIFICATES_PATH + certificate_file_name, 'w') as file:
        file.write(certificate.public_bytes(encoding=serialization.Encoding.PEM).decode())


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
    pem_cert = None
    with open(CERTIFICATES_PATH + certificate_file_name, "rb") as file:
        pem_cert = file.read()
    return x509.load_pem_x509_certificate(pem_cert, default_backend())


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
        write_certificate(root_certificate, root_certificate_file)

    if root_private_key_file:
        save_key(root_key, root_private_key_file)

    return root_certificate, root_key


def certificate_issuing(user_id, user_pwd_hash, root_certificate_file='root_certificate.pem',
                        root_private_key_file="root_private_key.pem", validity=30):
    """
    Create new certificate signed form the CA

    Parameters
    ----------

    user_id: str
        identifier of the user

    user_pwd_hash: str
        password hash of the user

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


class CRL:
    """
    Updatable certificate revocation list (CRL)
    """
    def __init__(self, root_certificate_file='root_certificate.pem', root_private_key_file="root_private_key.pem"):
        """
        self.revoked_certificates: List[RevokedCertificate]
            List of all the revoked certificates

        self.root_certificate_file: str
            file to store the root certificate

        self.root_private_key_file: str
            file to store the private key
        """
        self.revoked_certificates = []
        self.root_certificate_file = root_certificate_file
        self.root_private_key_file = root_private_key_file

    def revoke_certificate(self, certificate):
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
        self.revoked_certificates.append(builder.build(default_backend()))

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
        return cert_revocation_list.public_bytes(encoding=serialization.Encoding.PEM)

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
        self.revoke_certificate(certificate)
        return self.get_crl()


def is_revoked(certificate, crl_pem):
    """
    Check if a certificate is revoked in a particular CRL

    Parameters
    ----------
    certificate: Certificate
        certifficate to check

    crl_pem: Byte[]
        the correponding CRL in the pem format

    Returns
    -------
    bool

    """
    crl = x509.load_pem_x509_crl(crl_pem, backend=default_backend())
    return crl.get_revoked_certificate_by_serial_number(certificate.serial_number) != None
