from qrcodegen import *
from flask import Flask, request, redirect
from flask import request
from rsa_methods import *


def generate(qrcode: QrCode) -> str:
    border = 1
    parts: list[str] = []
    for y in range(qrcode.get_size()):
        for x in range(qrcode.get_size()):
            if qrcode.get_module(x,y):
                parts.append(f"M{x+border},{y+border}h1v1h-1z")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 {qrcode.get_size()+border*2} {qrcode.get_size()+border*2}" stroke="none">
<rect width="100%" height="100%" fill="#FFFFFF"/>
<path d="{" ".join(parts)}" fill="#000000"/>
</svg>
"""
def save_qr(encrypted_secret: str) -> None:
    address = str(urlenv_route+known_param) + str(base64.b64encode(encrypted_secret).decode('utf-8'))
    errlvl = QrCode.Ecc.HIGH
    qr = QrCode.encode_text(address, errlvl)
    fs = open("qrresume.svg", mode='w')
    fs.write(generate(qr))
    print(f"\nWrote: {address} to QR code svg.\n")


app = Flask(__name__)

urlenv_route = "youknow"
known_param = "thisparam"

@app.route("/"+urlenv_route, methods=['GET'])
def access():
    error = None
    if request.method != "GET":
        redirect("/")
    data = request.args.get(known_param)
    return f"<h1>show access {data}</h1>"

'''
if __name__ == "__main__":
    keys = generate_rsa(str(sys.argv[1]))
    rsa_private_key = keys[0]
    rsa_public_key = rsa_private_key.public_key() 
    signature = keys[1] 
    ciphertext = encrypt_secret(rsa_public_key, str(sys.argv[2]))
    plaintext = decrypt_ciphertext(rsa_private_key, ciphertext)

    print(f"\nCiphertext: {ciphertext}\n")
    print(f"\nbase64.b64encode(Ciphertext): {base64.b64encode(ciphertext).decode('utf-8')}\n")
    print(f"\nSignature: {signature}\n")

    # Correctness check
    assert(plaintext.decode() == str(sys.argv[2]))
    print(f"{plaintext.decode()} == {sys.argv[2]}")
    r = verify_signature(rsa_private_key, signature, str(sys.argv[1])),
    print(f"r: {r}")

    save_qr(ciphertext)
    exit(0)
'''
