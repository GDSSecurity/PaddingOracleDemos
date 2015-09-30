#!/usr/bin/env python 
"""Example web application vulnerable to the Padding Oracle attack.

Example web application vulnerable to the Padding Oracle attack. It uses
AES-128 with PKCS#7 padding and the same static password for both the
encryption key and initialisation vector. There is no HMAC or other message
integrity check.

The app provides two vulnerable methods that decrypt hex encoded values:

 * /echo?crypt=[..]
This method decrypts and returns the provided data. If the padding is incorrect
it shows 'decryption error'.

 * /check?crypt=[..]
This method checks for URL-encoded values in the decrypted data. It returns an
error if the fields ApplicationUsername or Password are missing. If the padding
is incorrect it treats the plaintext as empty and shows 'ApplicationUsername
missing' as well.

For debugging purposes there is also a method to encrypt a (URL-encoded)
plaintext:

 * /encrypt?plain=[..]

Testing:

# curl http://127.0.0.1:5000/encrypt?plain=ApplicationUsername%3Duser%26Password%3Dsesame
crypted: 484b850123a04baf15df9be14e87369[..]

# curl http://127.0.0.1:5000/echo?cipher=484b850123a04baf15df9be14e87369[..]
decrypted: ApplicationUsername=user&Password=sesame

# curl http://127.0.0.1:5000/check?cipher=484b850123a04baf15df9be14e87369[..]
decrypted: ApplicationUsername=user&Password=sesame
parsed: {'Password': ['sesame'], 'ApplicationUsername': ['user']}
"""

from flask import Flask, request
import urlparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import binascii

__author__ = "Georg Chalupar"
__email__ = "gchalupar@gdssecurity.com"
__copyright__ = "Copyright 2015, Gotham Digital Science Ltd"

KEY = "0123456789ABCDEF"
BLOCK_SIZE = 128
REQUIRED_VALUES = ["ApplicationUsername", "Password"]

app = Flask(__name__)

@app.route('/encrypt')
def generate():
    plain = request.args.get('plain', '')
    app.logger.debug('plain: {}'.format(repr(plain)))
    crypted = binascii.hexlify(encrypt(plain))
    app.logger.debug('crypted: {}'.format(crypted))
    return 'crypted: {}'.format(crypted)

@app.route('/echo')
def echo():
    """Decrypts the 'cipher' parameter and returns the plaintext. If the
    padding is incorrect it returns 'decryption error'."""
    crypt = request.args.get('cipher', '')
    app.logger.debug('cipher: {}'.format(crypt))
    try:
        plain = decrypt(binascii.unhexlify(crypt))
    except ValueError as e:
        app.logger.debug('decryption error: {}'.format(e))
        return 'decryption error'
    app.logger.debug('plain: {}'.format(plain))
    return 'decrypted: {}'.format(plain)

@app.route('/check')
def check():
    """Parse URL-encoded values in decrypted 'cipher' parameter. Returns an
    error if it does not find all values in REQUIRED_VALUES. A padding error is
    treated the same as way an empty plaintext string."""
    crypt = request.args.get('cipher', '')
    app.logger.debug('cipher: {}'.format(crypt))
    try:
        plain = decrypt(binascii.unhexlify(crypt))
    except ValueError as e:
        app.logger.debug('decryption error: {}'.format(e))
        plain = ''
    print "plain: {}".format(plain)
    values = urlparse.parse_qs(plain)
    print "decrypted values: {}".format(values)
    for name in REQUIRED_VALUES:
        if name not in values:
            return '{} missing'.format(name)
    return 'decrypted: {}\nparsed: {}'.format(plain, values)
    
def encrypt(plain):
    """Adds PKCS#7 padding and encrypts with AES-128."""
    iv = KEY
    backend = default_backend()
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_data = padder.update(bytes(plain)) + padder.finalize()
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    crypted = encryptor.update(padded_data) + encryptor.finalize()
    return crypted

def decrypt(crypted):
    """Decrypts with AES-128 and removes PKCS#7 padding."""
    iv = KEY
    backend = default_backend()
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    plain = decryptor.update(crypted)
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    unpadded_data = unpadder.update(plain) + unpadder.finalize()
    return unpadded_data


if __name__ == '__main__':
    app.run(debug=True)
