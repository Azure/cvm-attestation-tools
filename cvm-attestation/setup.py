# setup.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from setuptools import setup, find_packages

setup(
    name='attest',
    version='0.1',
    packages=find_packages(include=['src', 'src.*']),
    py_modules=['attest', 'read_report'],
    install_requires=[
        'Click',
    ],
    entry_points={
        'console_scripts': [
            'attest = attest:attest',
            'read_report=read_report:read_report',
        ],
    }
)