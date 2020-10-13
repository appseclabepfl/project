import unittest
from ca_core import *
from OpenSSL import crypto

class MyTestCase(unittest.TestCase):

    def test_Certificate(self):
        root_certificate, root_key = create_root_certificate('root_certificate.pem', "root_private_key.pem")
        certificate, private_key = certificate_issuing("user_id")
        self.assertEqual(True, verify_certificate(certificate, root_certificate))

    def test_crl(self):
        root_certificate, root_key = create_root_certificate('root_certificate.pem', "root_private_key.pem")
        certificate1, private_key1 = certificate_issuing("user_id")
        certificate2, private_key2 = certificate_issuing("user_id")
        certificate3, private_key3 = certificate_issuing("user_id")

        crl = CRL()
        _, crl_pem = crl.update_crl(certificate1)


        self.assertEqual(True, is_revoked(certificate1, crl_pem))
        self.assertEqual(False, is_revoked(certificate2, crl_pem))
        self.assertEqual(False, is_revoked(certificate3, crl_pem))

        crl2 = CRL()
        _, crl_pem = crl2.update_crl(certificate3)

        self.assertEqual(True, is_revoked(certificate1, crl_pem))
        self.assertEqual(False, is_revoked(certificate2, crl_pem))
        self.assertEqual(True, is_revoked(certificate3, crl_pem))

    def test_pkcs12_export(self):
        root_certificate, root_key = create_root_certificate('root_certificate.pem', "root_private_key.pem")
        certificate1, private_key1 = certificate_issuing("user_id")

        pkcs12 = create_pkcs12_bytes("certificates/issued/"+get_certificate_name(certificate1), "keys/"+"user_id.pem")

        f = open("test_pkcsformat.p12", 'wb')

        f.write(pkcs12)

        f.close()

        p12 = crypto.load_pkcs12(open("test_pkcsformat.p12", 'rb').read())
        cert = p12.get_certificate()     # (signed) certificate object
        key = p12.get_privatekey()      # private key.





if __name__ == '__main__':
    unittest.main()
