# Flask-Basic-Roles
A simple Flask library for adding simple roles to basic web authentication.

## What's `flask-basic-roles` for?

Have you ever designed a simple web API or website that you wanted a little more than [basic authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) for, but didn't want a full-blown database for user management?

The goal of`flask-basic-roles` is to bridge that gap and make it as simple as possible to add some role based security to a basic [Flask](http://flask.pocoo.org/) based web service/REST API.

## How do I get it?

Install via pip:

```
pip install flask_basic_roles
```

## How do I use it?

Here's a very simple example building upon the `Flask` quickstart guide.

```python
from flask import Flask
from flask_basic_roles import BasicRoleAuth
app = Flask(__name__)
auth = BasicRoleAuth()

# Let's add some users.
auth.add_user(user='bob', password='secret123', roles='admin')
auth.add_user(user='alice', password='drowssap', roles=('editor','photographer'))
auth.add_user(user='steve', password='12345', roles='editor')

@app.route("/")
def index():
    return "Welcome to my page!"

@app.route("/postings")
@auth.require(roles={
	'PATCH,PUT': ('editor', 'admin'),
    'DELETE': ('admin')
})
def postings_page():
	return "Welcome to the postings editing page!"
    
@app.route("/admin")
@auth.require(roles='admin')
def admin_page():
	return "Welcome to the admin page!"

# We can secure by user too.
@app.route("/bob")
@auth.require(users='bob')
def bob_page():
	return "Welcome to Bob's special page!"

# Steve and users with a 'photographer' or 'admin' role can access this.
@app.route("/photography")
@auth.require(users='steve', roles=('admin', 'photographer'))
def photography_page():
	return "Welcome to the photography page!"
    
if __name__ == "__main__":
    app.run()
```

### But isn't putting passwords in code a bad idea?

Yes! This is only supported in the API for demonstration and testing purposes. Users and their roles can (and should!) instead be specified in a file loaded via `auth.load_from_file("file path here")`.

This file defines each user one line at a time in the format
```
<user>:<password>:<role_1>,<role_2>,...<role_n>`
```

In the case of the above example, this would look like:

```
bob:secret123:admin
alice:drowssap:editor,photographer
steve:12345:editor
```

### What if I'm too lazy to make that file?
This file can also be generated from a configured `BasicRoleAuth` object via the `auth.save_to_file("file path here")` function.

##Anything else I should know before using this in my own projects?

1. `flask-basic-roles` is intended for small projects ideally **without** user registration (i.e. **not** a forum website) and for a small predefined number of users. If you are building something intended for a big audience, don't use this library!

2. `flask-basic-roles`does **not** provide transport level security. If you are building something for using outside of your LAN, secure it with HTTPS via a reverse proxy like [NGINX](https://www.nginx.com/).
