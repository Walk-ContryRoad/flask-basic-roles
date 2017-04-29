# Flask-Basic-Roles [![Build Status](https://travis-ci.org/ownaginatious/flask-basic-roles.svg?branch=master)](https://travis-ci.org/ownaginatious/flask-basic-roles)
A Flask library for extending basic web authentication with multiple users and roles.

## What's `flask-basic-roles` for?

Have you ever designed a simple web app that you wanted a little more than [basic authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) for, but didn't really have a need for full-blown sessions and a database for user management?

The goal of`flask-basic-roles` is to bridge that gap and make it as simple as possible to add some role based security to a [Flask](http://flask.pocoo.org/) based web service/REST API.

## How do I get it?

Install via pip:

```
pip install flask_basic_roles
```

## How do I use it?

Here's a very simple example building upon the `Flask` quickstart guide that tries to demonstrate the functionality of this library.

```python
from flask import Flask
from flask_basic_roles import BasicRoleAuth
app = Flask(__name__)
auth = BasicRoleAuth()

# Let's add some users.
auth.add_user(user='bob', password='secret123', roles='producer')
auth.add_user(user='alice', password='drowssap', roles=('producer','consumer'))
auth.add_user(user='bill', password='54321')
auth.add_user(user='steve', password='12345', roles='admin')

# Only producers and admins can post, while consumers can only get.
# Admins can also perform all other verbs.
@app.route("/task")
@auth.require(roles={
    'POST': 'producer',
    'GET': 'consumer',
    'DELETE,POST,PATCH,PUT,GET': 'admin'
})
def tasks_endpoint(methods=(...)):
    return "Here tasks get produced and consumed!"

# We can secure by user too. Steve can use any verb on this
# endpoint and everyone else is denied access.
@app.route("/task_status")
@auth.require(users='steve')
def task_status_endpoint(methods=(...)):
    return "Here are the task statuses!"

# Alice, Bill and users with an 'admin' role can access this, while everyone
# else is denied on all verbs.
@app.route("/task_failures")
@auth.require(users=('alice', 'bill'), roles='admin')
def task_failures(methods=(...)):
    return "Here are the task failures!"

# Everyone including unauthenticated users can view task results.
@app.route("/task_results")
def task_results(methods=(...)):
    return "Here are the task results!"

if __name__ == "__main__":
    app.run()
```

### But isn't putting passwords in code a bad idea?

Yes! This is only supported in the API for demonstration and testing purposes. Users and their roles can (and should!) instead be specified in a file loaded via `auth.load_from_file("file path here")` or `auth = BasicRoleAuth(user_file="file path here")`.

This file defines each user one line at a time in the following format:
```
<user>:<password>:<role_1>,<role_2>,...<role_n>`
```

In the case of the above example, this would look like:

```
bob:secret123:producer
alice:drowssap:producer,consumer
bill:54321:
steve:12345:admin
```

### What if I'm too lazy to make that file?
This file can also be generated from a configured `BasicRoleAuth` object via the `auth.save_to_file("file path here")` function.

### What happens if a user fails to authenticate or has no authorization?

If a user fails to authenticate, then `BasicRoleAuth.no_authentication` is executed to generate the response.

If a user authenticates (i.e. they provide a matching username and password), but their "account" has no authorization to perform the action (e.g. in the example above, `bob` attempting to do `DELETE` on `/tasks`), then `BasicRoleAuth.no_authorization` is executed to generate the response.

These methods can be overridden as follows:

```python
def no_authentication():
    return Response("My custom response here", 401)

auth = BasicRoleAuth()
auth.no_authentication = no_authentication
```

## Anything else I should know before using this in my own projects?

1. `flask-basic-roles` is intended for small projects ideally **without** user registration (i.e. **not** a forum website or store) and for a small predefined number of users. If you are building something intended for a big audience, don't use this library!

2. `flask-basic-roles`does **not** provide transport level security. If you are building something for use outside of your LAN, secure it with HTTPS via a reverse proxy like [NGINX](https://www.nginx.com/).

3. Passwords are in **plain text**. Support may be added later for [digest access authentication](https://en.wikipedia.org/wiki/Digest_access_authentication). You should **not** use passwords you tend to use in a lot of different places with this library.
