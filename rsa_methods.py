import sys
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

if len(sys.argv) < 3:
    print(f"\nUsage: python {sys.argv[0]} <signing_message> <plain_text>\n")
    exit(1)

'''
Generates a tuple after signing with a message. 
'''
def generate_rsa(message: str) -> (rsa.RSAPrivateKey,rsa.RSAPublicKey, bytes):
    private_key = rsa.generate_private_key(65537,4096)
    signature = private_key.sign(
                    message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
    return (private_key,private_key.public_key(),base64.b64encode(signature))

'''
Encrypt a plaintext with public key
secret is type: bytes. base64 encode so it can be used in qr code url.
'''
def encrypt_secret(public_key: rsa.RSAPublicKey, message: str) -> bytes:
    secret = public_key.encrypt(
                                message.encode('utf-8'),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
    return base64.b64encode(secret)

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

keys = generate_rsa(str(sys.argv[1]))
rsa_private_key = keys[0]
rsa_public_key = keys[1] 
signature = keys[2] 
ciphertext = encrypt_secret(rsa_public_key, str(sys.argv[2]))
plaintext = decrypt_ciphertext(rsa_private_key, base64.b64decode(ciphertext))

print(f"\nCiphertext: {ciphertext.decode()}\n")
print(f"\nSignature: {signature.decode()}\n")

# Correctness check
assert(plaintext.decode() == str(sys.argv[2]))
print(f"{plaintext.decode()} == {sys.argv[2]}")
