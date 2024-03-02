import json
from flask import Flask, jsonify, request
import jwt
from datetime import datetime, timedelta
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

app = Flask(__name__)

public_keys = {}

def load_public_keys():
    global public_keys

    # Check if the file exists and is not empty
    if os.path.exists('public_key.json') and os.path.getsize('public_key.json') > 0:
        try:
            with open('public_key.json', 'r') as f:
                public_keys = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    else:
        # If the file is empty or doesn't exist, return an empty dictionary
        return {}

    return public_keys

# Function to generate RSA key pair
def generate_rsa_key_pair():
    global public_keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Key size in bits (2048 bits is commonly used)
        backend=default_backend()
    )

    # Convert private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_str = private_key_pem.decode()

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Assuming public_key_pem is the PEM encoded RSA public key
    modulus_bytes = public_key.public_numbers().n.to_bytes(256, byteorder='big')  # 256 bytes for a 2048-bit key
    modulus_b64url = base64.urlsafe_b64encode(modulus_bytes).rstrip(b'=').decode()

    # public_key_str = public_key_pem.decode()

    try:
        with open('public_key.json', 'r') as f:
            public_keys = json.load(f)
    except FileNotFoundError:
        pass

    key_id = f"key{len(public_keys) + 1}"

    expiry_timestamp = (datetime.utcnow() + timedelta(days=1)).timestamp()

    key_info = {
        "kid": key_id,
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "n": modulus_b64url,
        "exp": expiry_timestamp
    }

    public_keys[key_id] = key_info


    with open('public_key.json', 'w') as f:
        json.dump(public_keys, f)

    public_keys = load_public_keys()

    return private_key, key_id

# Function to generate RSA key pair
def generate_expired_rsa_key_pair():
    global public_keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Key size in bits (2048 bits is commonly used)
        backend=default_backend()
    )

    # Convert private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_str = private_key_pem.decode()

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Assuming public_key_pem is the PEM encoded RSA public key
    modulus_bytes = public_key.public_numbers().n.to_bytes(256, byteorder='big')  # 256 bytes for a 2048-bit key
    modulus_b64url = base64.urlsafe_b64encode(modulus_bytes).rstrip(b'=').decode()

    # public_key_str = public_key_pem.decode()

    try:
        with open('public_key.json', 'r') as f:
            public_keys = json.load(f)
    except FileNotFoundError:
        pass

    key_id = f"key{len(public_keys) + 1}"

    expiry_timestamp = (datetime.utcnow() - timedelta(days=1)).timestamp()

    key_info = {
        "kid": key_id,
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "n": modulus_b64url,
        "exp": expiry_timestamp
    }

    public_keys[key_id] = key_info


    with open('public_key.json', 'w') as f:
        json.dump(public_keys, f)

    public_keys = load_public_keys()

    return private_key, key_id, expiry_timestamp

# Route to retrieve JWKS
@app.route('/.well-known/jwks.json')
def get_jwks():
    current_time = datetime.utcnow().timestamp()
    valid_keys = []

    for kid, key_info in public_keys.items():
        expiry = key_info["exp"] if "exp" in key_info else 0
        if expiry > current_time:
            # Key is not expired, include it in the JWKS response
            valid_keys.append({
                "kid": kid,
                "alg": key_info["alg"],
                "kty": key_info["kty"],
                "use": key_info["use"],
                "n": key_info["n"],
                "e": "AQAB",
                "exp": key_info["exp"]
            })

    jwks = {"keys": valid_keys}

    return jsonify(jwks)

# Route for authentication
@app.route('/auth', methods=['POST'])
def auth():
    # Check if the 'expired' query parameter is present
    expired = request.args.get('expired') == 'true'

    if expired:
        # Generate an expired key pair and set an expired expiry
        expired_private_key, key_id, expiry = generate_expired_rsa_key_pair()

        # Generate JWT using the expired key pair and expiry
        token = jwt.encode({'username': 'example_user', 'exp': expiry}, expired_private_key, algorithm='RS256', headers={'kid': key_id})
    else:
        # Generate a new key pair and token with current expiry
        private_key, key_id = generate_rsa_key_pair()
        token = jwt.encode({'username': 'example_user'}, private_key, headers = {'kid': key_id, 'alg': 'RS256'})
    print(token)
    return token

if __name__ == '__main__':
    app.run(debug=True, port=8080)
