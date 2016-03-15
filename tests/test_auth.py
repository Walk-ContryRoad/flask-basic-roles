from __future__ import absolute_import, division, \
                       print_function, unicode_literals
from collections import namedtuple
from tempfile import NamedTemporaryFile
import os
import unittest
from flask_basic_roles import BasicRoleAuth, \
                              UserAlreadyDefinedError

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

    def try_auth(self, username, password, method, users=(), roles=()):

        # Reset authentication/authorization records.
        self.not_authenticated, self.not_authorized = False, False

        # Simulate the decorator on a noop function.
        self.auth.require(users=users, roles=roles,
                          test_auth=BasicCred(username, password),
                          test_method=method)(lambda: True)()
        a, b = not self.not_authenticated, not self.not_authorized

        # Reset authentication/authorization records.
        self.not_authenticated, self.not_authorized = False, False
        return a, b

    def test_no_authentication_bad_pass(self):
        self.auth.add_user('user_a', 'foo')
        authenticated, _ = self.try_auth('user_a', 'bar', 'GET')
        self.assertFalse(authenticated)

    def test_no_authentication_bad_user(self):
        self.auth.add_user('user_a', 'foo')
        authenticated, _ = self.try_auth('dollin', 'bar', 'GET')
        self.assertFalse(authenticated)

    def test_authentication(self):
        self.auth.add_user('user_a', 'foo')
        authenticated, _ = self.try_auth('user_a', 'foo', 'GET')
        self.assertTrue(authenticated)

    def test_no_authorization(self):
        self.auth.add_user('user_a', 'foo')
        _, authorized = self.try_auth('user_a', 'foo', 'GET',
                                      users='billy')
        self.assertFalse(authorized)

    def test_authorization_by_user(self):
        self.auth.add_user('user_a', 'foo')
        a, b = self.try_auth('user_a', 'foo', 'GET',
                             users='user_a')
        self.assertTrue(a and b)

    def test_authorization_by_role(self):
        self.auth.add_user('test_1', 'foo')
        self.auth.add_roles('test_1', ('admin', 'system'))
        self.auth.add_user('test_2', 'bar')
        self.auth.add_roles('test_2', 'admin')

        # Both users are admins
        a, b = self.try_auth('test_1', 'foo', 'GET',
                             roles='admin')
        self.assertTrue(a and b)
        a, b = self.try_auth('test_2', 'bar', 'GET',
                             roles='admin')
        self.assertTrue(a and b)

        # One user is system and one is not.
        a, b = self.try_auth('test_1', 'foo', 'GET',
                             roles='system')
        self.assertTrue(a and b)
        a, b = self.try_auth('test_2', 'bar', 'GET',
                             roles='system')
        self.assertFalse(b)

    def test_authorization_by_role_2(self):

        self.auth.add_user('test_3', 'moo')
        self.auth.add_roles('test_3', ('system', 'user'))
        self.auth.add_user('test_4', 'choo')
        self.auth.add_roles('test_4', ('database', 'user'))

        # Check test_3 user access.
        a, b = self.try_auth('test_3', 'moo', 'GET',
                             roles='system')
        self.assertTrue(a and b)
        a, b = self.try_auth('test_3', 'moo', 'GET',
                             roles='database')
        self.assertFalse(b)
        a, b = self.try_auth('test_3', 'moo', 'GET',
                             roles='user')
        self.assertTrue(a and b)

        # Check test_4 user access.
        a, b = self.try_auth('test_4', 'choo', 'GET',
                             roles='system')
        self.assertFalse(a and b)
        a, b = self.try_auth('test_4', 'choo', 'GET',
                             roles='database')
        self.assertTrue(b)
        a, b = self.try_auth('test_4', 'choo', 'GET',
                             roles='user')
        self.assertTrue(a and b)

    def test_method_roles(self):

        self.auth.add_user('test_1', 'password_1')
        self.auth.add_roles('test_1', 'user')

        self.auth.add_user('test_2', 'password_2')
        self.auth.add_roles('test_2', 'system')

        self.auth.add_user('test_3', 'password_3')
        self.auth.add_roles('test_3', 'admin')

        roles = {
            'GET': ('user', 'admin'),
            'POST,PATCH,PUT,DELETE': 'admin',
            'DELETE': 'system'
        }

        # Check test_1 user access.
        a, b = self.try_auth('test_1', 'password_1', 'GET',
                             roles=roles)
        self.assertTrue(a and b)

        # Ensure test_1 user cannot do modifications.
        for v in ('POST', 'PUT', 'PATCH'):
            a, b = self.try_auth('test_1', 'password_1', v,
                                 roles=roles)
            self.assertFalse(b)

        # Check test_2 user access.
        for v in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'):
            a, b = self.try_auth('test_2', 'password_2', v,
                                 roles=roles)
            if v == 'DELETE':
                self.assertTrue(a and b)
            else:
                self.assertFalse(b)

        # Check test_3 user access.
        for v in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE'):
            a, b = self.try_auth('test_3', 'password_3', v,
                                 roles=roles)
            self.assertTrue(a and b, "User test_3 with %s" % v)

if __name__ == '__main__':
    unittest.main()
