from __future__ import absolute_import, division, print_function, unicode_literals
from tempfile import NamedTemporaryFile
import os
import unittest
from flask_basic_roles import BasicRoleAuth, UserAlreadyDefinedError

class TestDataStructure(unittest.TestCase):

    def setUp(self):
        self.auth = BasicRoleAuth()

    def test_add_user(self):
        self.auth.add_user('dillon', 'foo')
        self.assertIn('dillon', self.auth.users)

    def test_delete_user(self):
        self.auth.add_user('dillon', 'foo')
        self.assertIn('dillon', self.auth.users)
        self.auth.delete_user('dillon')
        self.assertNotIn('dillon', self.auth.users)

    def test_add_user_multiple_times(self):
        self.auth.add_user('dillon', 'foo')
        with self.assertRaises(UserAlreadyDefinedError):
            self.auth.add_user('dillon', 'bar')

    def test_add_role_single(self):
        self.auth.add_user('dillon', 'foo')
        self.auth.add_roles('dillon', 'admin')
        self.auth.add_roles('dillon', 'reader')
        self.assertEqual(self.auth.roles['dillon'], 
                         set(('admin', 'reader')))

    def test_delete_role_single(self):
        self.auth.add_user('dillon', 'foo')
        self.auth.add_roles('dillon', ('admin', 'reader'))
        self.assertEqual(self.auth.roles['dillon'], 
                         set(('admin', 'reader')))
        self.auth.delete_roles('dillon', 'admin')
        self.assertEqual(self.auth.roles['dillon'], 
                         set(('reader',)))

    def test_add_role_multiple(self):
        self.auth.add_user('dillon', 'foo')
        self.auth.add_roles('dillon', ('admin', 'reader'))
        self.assertEqual(self.auth.roles['dillon'], 
                         set(('admin', 'reader')))

    def test_delete_role_single(self):
        self.auth.add_user('dillon', 'foo')
        self.auth.add_roles('dillon', ('admin', 'reader'))
        self.assertEqual(self.auth.roles['dillon'], 
                         set(('admin', 'reader')))
        self.auth.delete_roles('dillon', set(('admin', 'reader')))
        self.assertEqual(self.auth.roles['dillon'], set())

    def test_add_role_duplicate(self):
        self.auth.add_user('dillon', 'foo')
        self.auth.add_roles('dillon', ('admin', 'reader'))
        self.auth.add_roles('dillon', 'reader')
        self.assertEqual(self.auth.roles['dillon'], 
                         set(('admin', 'reader')))

    def test_load_config_file(self):

        with NamedTemporaryFile(mode='w+t') as f:

            f.write("user_a:password_a:role_a,role_b\n")
            f.write("user_b:password_b:role_b,role_c\n")
            f.write("user_c:password_c:role_c,role_c\n")
            f.flush()
            self.auth.load_from_file(f.name)

        # Assert user equality.
        self.assertEqual(self.auth.users, 
                        {
                            'user_a': 'password_a',
                            'user_b': 'password_b',
                            'user_c': 'password_c'
                        })

        # Assert role equality.
        self.assertEqual(self.auth.roles, 
                        {
                            'user_a': set(('role_a', 'role_b')),
                            'user_b': set(('role_b', 'role_c')),
                            'user_c': set(('role_c', 'role_c'))
                        })

    def test_save_config_file(self):

        self.auth.add_user('user_a', 'password_a')
        self.auth.add_user('user_b', 'password_b')
        self.auth.add_user('user_c', 'password_c')

        self.auth.add_roles('user_a', ('role_a', 'role_b'))
        self.auth.add_roles('user_b', ('role_b', 'role_c'))
        self.auth.add_roles('user_c', ('role_c', 'role_c'))

        with NamedTemporaryFile(mode='w+t') as f:

            self.auth.save_to_file(f.name)

            expected = [
                "user_a:password_a:role_a,role_b",
                "user_b:password_b:role_b,role_c",
                "user_c:password_c:role_c"
            ]

            for a, e in zip(f.readlines(), expected):
                self.assertEqual(a.strip(), e)

if __name__ == '__main__':
    unittest.main()
