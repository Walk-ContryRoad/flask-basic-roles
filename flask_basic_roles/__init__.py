from __future__ import absolute_import, division, print_function, unicode_literals
from collections import defaultdict
from functools import wraps
from io import open
from flask import request
from flask import Response


class BasicRoleAuthError(Exception):
    pass


class UserAlreadyDefinedError(BasicRoleAuthError):
    pass


class UserNotDefined(BasicRoleAuthError):
    pass


class BadRoleError(BasicRoleAuthError):
    pass


class BasicRoleAuth(object):

    def __init__(self, user_file=None):

        self.users = {}
        self.roles = defaultdict(set)

        if user_file:
            self.load_from_file(user_file)

    def load_from_file(self, user_file):

        with open(user_file, 'r+t', encoding='utf8') as f:
            for l in f.readlines():
                user, password, roles = l.strip().split(':', 2)
                roles = roles.split(',')
                self.add_user(user, password)
                self.add_roles(user, roles)

    def save_to_file(self, user_file):

        with open(user_file, 'w+t', encoding='utf8') as f:
            for user, password in sorted(self.users.items()):
                roles = sorted(list(self.roles[user]))
                f.write("%s:%s:%s\n" % (user, password, ','.join(roles)))

    def add_user(self, user, password, roles=None):
        if user in self.users:
            raise UserAlreadyDefinedError(user)
        self.users[user] = password
        if roles:
            self.add_roles(user, roles)

    def delete_user(self, user):
        if user in self.users:
            del self.users[user]
        if user in self.roles:
            del self.roles[user]

    def add_roles(self, user, roles):

        if user not in self.users:
            raise UserNotDefined(user)
        roles = (roles,) if isinstance(roles, basestring) else roles
        for role in roles:
            if ',' in role:
                raise BadRoleError('\',\' not allowed in role name (%s) '
                                   'for user %s' % (role, user))
            self.roles[user].add(role)

    def delete_roles(self, user, roles):

        if user not in self.users:
            raise UserNotDefined(user)
        roles = (roles,) if isinstance(roles, basestring) else roles
        for role in roles:
            self.roles[user].remove(role)

    def no_authentication(self):
        """Sends a 401 response that enables basic auth"""
        return Response(
                'User identity could not be verified.\n'
                'Please login with proper credentials', 401,
                {
                    'WWW-Authenticate': 'Basic realm="Login Required"'
                })

    def no_authorization(self):
        """Sends a 401 response that enables basic auth"""
        return Response(
                'The authenticated user is not authorized for the '
                'attempted operation.', 401)

    def require(self, users=(), roles=(), test_auth=None):

        if isinstance(users, basestring):
            users = (users,)
        if isinstance(roles, basestring):
            roles = (roles,)
        roles = set(roles)

        def loaded_decorated(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                auth = test_auth or request.authorization
                authenticated = auth and (auth.username in self.users) and \
                    self.users[auth.username] == auth.password
                if not authenticated:
                    return self.no_authentication()
                if users or roles:
                    auth_as_user = auth.username in users
                    auth_as_role = roles & self.roles[auth.username]
                    if not auth_as_user and not auth_as_role:
                        return self.no_authorization()
                return f(*args, **kwargs)
            return decorated
        return loaded_decorated
