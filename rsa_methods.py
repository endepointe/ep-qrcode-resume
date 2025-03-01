import sys
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.exceptions import InvalidSignature

if len(sys.argv) < 3:
    print(f"\nUsage: python {sys.argv[0]} <signing_message> <plain_text>\n")
    exit(1)

'''
Generates a tuple after signing with a message. 
'''
def generate_rsa(signing_message: str) -> (rsa.RSAPrivateKey, bytes):
    private_key = rsa.generate_private_key(65537,4096)
    signature = private_key.sign(
                    signing_message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
    return (private_key,signature)

'''
Encrypt a plaintext with public key
secret is type: bytes. base64 encode so it can be used in qr code url.
'''
def encrypt_secret(public_key: rsa.RSAPublicKey, plain_text: str) -> bytes:
    secret = public_key.encrypt(
                                plain_text.encode('utf-8'),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
    return secret

def decrypt_ciphertext(private_key: rsa.RSAPrivateKey, ciphertext: str) -> bytes:
    plaintext = private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
    return plaintext 

def verify_signature(private_key: rsa.RSAPrivateKey, signature: bytes, signing_message: str) -> bool:
    try:
        public_key = private_key.public_key()
        public_key.verify(
                    signature,
                    signing_message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
        )
        return True
    except InvalidSignature as ISE:
        print(f"ISE: {ISE}")
        return False
    except Exception as E:
        print(f"some error occurred: {E}")
