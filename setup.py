#! /usr/bin/env python
from setuptools import setup, find_packages
from io import open

setup(
    name='flask_basic_roles',
    packages = find_packages (exclude = ["tests",]),
    version='0.1',
    description='A plugin for adding very simple users + roles to a flask app',
    author='Dillon Dixon',
    author_email='dillondixon@gmail.com',
    url='https://github.com/ownaginatious/flask_basic_roles',
    download_url='https://github.com/ownaginatious/flask_basic_roles/tarball/0.1',
    license='MIT',
    keywords=['flask', 'python', 'authentication', 'authorization'],
    classifiers=[
        'Framework :: Flask',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5'
    ],
    install_requires = [line.strip ()
                        for line in open ("requirements.txt", "r",
                                          encoding="utf-8").readlines ()],
)
