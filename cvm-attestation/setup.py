# setup.py
from setuptools import setup, find_packages

setup(
    name='attest',
    version='0.1',
    packages=find_packages(),
    py_modules=['attest', 'tpm_wrapper'],  # Include the attest module
    install_requires=[
        'Click',
    ],
    entry_points={
        'console_scripts': [
            'attest = attest:main',
        ],
    }
)