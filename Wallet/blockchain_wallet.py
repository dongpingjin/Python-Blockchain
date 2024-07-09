import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5


import binascii

class Wallet(object):
    def __init__(self):
        random_gen = Crypto.Random.new().read
        self._private_key = RSA.generate(1024, random_gen)
        self._public_key = self._private_key.publickey()
        self._signer = PKCS1_v1_5.new(self._private_key)
        pass
        
    @property
    def address(self):
        """We take a shortcut and say address is public key"""
        return binascii.hexlify(self._public_key.exportKey(format='DER')).decode('ascii')

    def sign(self, message):
        """
        Sign a message with this wallet
        """
        h = SHA.new(message.encode('utf8'))
        return binascii.hexlify(self._signer.sign(h)).decode('ascii')
    
    
def verify_signature(wallet_address, message, signature):
    """
    Check that the provided `signature` corresponds to `message`
    signed by the wallet at `wallet_address`
    """
    pubkey = RSA.importKey(binascii.unhexlify(wallet_address))
    verifier = PKCS1_v1_5.new(pubkey)
    h = SHA.new(message.encode('utf8'))
    print("h", h)
    return verifier.verify(h, binascii.unhexlify(signature))


# Check that the wallet signing functionality works
w1 = Wallet()
# print(binascii.hexlify(w1._public_key.exportKey(format='OpenSSH')).decode('utf-8'))
# print(binascii.hexlify(w1._public_key.exportKey(format='OpenSSH')).decode('ascii'))
# aaa = w1._public_key.exportKey(format='OpenSSH')
#
# print(aaa.decode('ascii'))
# print(str(aaa))
# print(aaa.decode('utf-8'))
# print(aaa.decode('chinese'))
#
#
# bbb = binascii.hexlify(aaa)
# print(bbb.decode('ascii'))
# print(str(bbb))
# print(bbb.decode('utf-8'))
# print(bbb.decode('chinese'))

# print(w1._private_key)
# signature = w1.sign('foobar')
# print(signature)
print(w1.address)
# print(verify_signature(w1.address, 'foobar', signature))
# print(verify_signature(w1.address, 'rogue message', signature))
#
# assert verify_signature(w1.address, 'foobar', signature)
# assert not verify_signature(w1.address, 'rogue message', signature)