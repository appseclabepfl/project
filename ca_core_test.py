import unittest
from ca_core import *


class MyTestCase(unittest.TestCase):


    def test_Certificate(self):
        root_certificate, root_key = create_root_certificate('root_certificate.pem', "root_private_key.pem")
        certificate, private_key = certificate_issuing("user_id", "user_password")
        self.assertEqual(True, verify_certificate(certificate, root_certificate))

    def test_crl(self):
        root_certificate, root_key = create_root_certificate('root_certificate.pem', "root_private_key.pem")
        certificate1, private_key1 = certificate_issuing("user_id", "user_password")
        certificate2, private_key2 = certificate_issuing("user_id", "user_password")

        crl = CRL()
        crl_pem = crl.update_crl(certificate1)

        self.assertEqual(True, is_revoked(certificate1, crl_pem))
        self.assertEqual(False, is_revoked(certificate2, crl_pem))


if __name__ == '__main__':
    unittest.main()
