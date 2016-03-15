from __future__ import absolute_import, division, print_function, unicode_literals
from collections import namedtuple
from tempfile import NamedTemporaryFile
import os
import unittest
from flask_basic_roles import BasicRoleAuth, UserAlreadyDefinedError

BasicCred = namedtuple('BasicCred', ['username', 'password'])

class TestAuth(unittest.TestCase):

    def setUp(self):

        self.not_authenticated = False
        self.not_authorized = False

        def log_not_authenticated():
            self.not_authenticated = True

        def log_not_authorized():
            self.not_authorized = True

        # Override the no_authentication/no_authorization functions
        # so that failures to authenticate/authorize will be recorded.
        self.auth = BasicRoleAuth()
        self.auth.no_authentication = log_not_authenticated
        self.auth.no_authorization = log_not_authorized

    def try_auth(self, username, password, users=(), roles=()):

        # Reset authentication/authorization records.
        self.not_authenticated, self.not_authorized = False, False

        # Simulate the decorator on a noop function.
        self.auth.auth_required(users=users, roles=roles,
            test_auth=BasicCred(username, password))(lambda: True)()
        a, b = not self.not_authenticated, not self.not_authorized

        # Reset authentication/authorization records.
        self.not_authenticated, self.not_authorized = False, False
        return a, b

    def test_no_authentication_bad_pass(self):
        self.auth.add_user('dillon', 'foo')
        authenticated, _ = self.try_auth('dillon', 'bar')
        self.assertFalse(authenticated)

    def test_no_authentication_bad_user(self):
        self.auth.add_user('dillon', 'foo')
        authenticated, _ = self.try_auth('dollin', 'bar')
        self.assertFalse(authenticated)

    def test_authentication(self):
        self.auth.add_user('dillon', 'foo')
        authenticated, _ = self.try_auth('dillon', 'foo')
        self.assertTrue(authenticated)

    def test_no_authorization(self):
        self.auth.add_user('dillon', 'foo')
        _, authorized = self.try_auth('dillon', 'foo',
                                      users='billy')
        self.assertFalse(authorized)

    def test_authorization_by_user(self):
        self.auth.add_user('dillon', 'foo')
        a, b = self.try_auth('dillon', 'foo',
                             users='dillon')
        self.assertTrue(a and b)

    def test_authorization_by_role(self):
        self.auth.add_user('test_1', 'foo')
        self.auth.add_roles('test_1', ('admin', 'system'))
        self.auth.add_user('test_2', 'bar')
        self.auth.add_roles('test_2', 'admin')

        # Both users are admins
        a, b = self.try_auth('test_1', 'foo',
                             roles='admin')
        self.assertTrue(a and b)
        a, b = self.try_auth('test_2', 'bar',
                             roles='admin')
        self.assertTrue(a and b)

        # One user is system and one is not.
        a, b = self.try_auth('test_1', 'foo',
                             roles='system')
        self.assertTrue(a and b)
        a, b = self.try_auth('test_2', 'bar',
                             roles='system')
        self.assertFalse(b)


    def test_authorization_by_role_2(self):

        self.auth.add_user('test_3', 'moo')
        self.auth.add_roles('test_3', ('system', 'user'))
        self.auth.add_user('test_4', 'choo')
        self.auth.add_roles('test_4', ('database', 'user'))

        # Check test_3 user access.
        a, b = self.try_auth('test_3', 'moo',
                             roles='system')
        self.assertTrue(a and b)
        a, b = self.try_auth('test_3', 'moo',
                             roles='database')
        self.assertFalse(b)
        a, b = self.try_auth('test_3', 'moo',
                             roles='user')
        self.assertTrue(a and b)

        # Check test_4 user access.
        a, b = self.try_auth('test_4', 'choo',
                             roles='system')
        self.assertFalse(a and b)
        a, b = self.try_auth('test_4', 'choo',
                             roles='database')
        self.assertTrue(b)
        a, b = self.try_auth('test_4', 'choo',
                             roles='user')
        self.assertTrue(a and b)

if __name__ == '__main__':
    unittest.main()
