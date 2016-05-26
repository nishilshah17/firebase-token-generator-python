try:
    basestring
except NameError:  # Python 3
    basestring = str
from firebase_token_generator import create_token
import unittest

email = "test_account@invalid.com"
with open('test_rsa') as f:
    key = f.read()

class TestTokenGenerator(unittest.TestCase):

    def test_smoke_test(self):
        token = create_token(email, key, "foo")
        self.assertIsInstance(token, basestring)

    def test_malformed_email(self):
        with self.assertRaises(ValueError):
            token = create_token(1234567890, key, "foo")

    def test_malformed_private_key(self):
        with self.assertRaises(ValueError):
            token = create_token(email, 1234, "foo")

    def test_malformed_uid(self):
        with self.assertRaises(ValueError):
            token = create_token(email, key, 1234)

    def test_forbidden_claim(self):
        with self.assertRaises(ValueError):
            token = create_token(email, key, "foo", {"iss": "not-my-app"})

    def test_uid_max_length(self):
        #length:                                   10        20        30        40        50        60        70        80        90       100       110       120       130       140       150       160       170       180       190       200       210       220       230       240       250   256
        token = create_token(email, key, "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456")
        self.assertIsInstance(token, basestring)

    def test_uid_too_long(self):
        with self.assertRaises(ValueError):
            #length:                                  10        20        30        40        50        60        70        80        90       100       110       120       130       140       150       160       170       180       190       200       210       220       230       240       250    257
            token = create_token(email, key, "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567")

    def test_uid_min_length(self):
        token = create_token(email, key, "")
        self.assertIsInstance(token, basestring)

if __name__ == '__main__':
    unittest.main()
