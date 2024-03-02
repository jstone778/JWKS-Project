# Proper imports for the JWKS server
import json
from flask import Flask, jsonify, request
import jwt
from datetime import datetime, timedelta
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

# Creates the app
app = Flask(__name__)

# Initializes a global variable for the public keys
public_keys = {}

# The purpose of this function is to load in the public keys
# from the json file that is in the github
def load_public_keys():
    # Make sure that it is accessing the global variable
    global public_keys

    # Check if the file exists and is not empty
    if os.path.exists('public_key.json') and os.path.getsize('public_key.json') > 0:
        try:
            # Opens and reads the file if so
            with open('public_key.json', 'r') as f:
                public_keys = json.load(f)
        # Throws an exception if not
        except (FileNotFoundError, json.JSONDecodeError):
            pass
    else:
        # If the file is empty or doesn't exist, return an empty dictionary
        return {}

    # Returns the global variable for the public keys
    return public_keys

# The purpose of this function is to generate the 
# RSA key pairs with all of the proper information
def generate_rsa_key_pair():
    global public_keys
    # Generates the private key for the pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generates the public key for the pair
    public_key = private_key.public_key()

    # Encodes the key using base64url
    modulus_bytes = public_key.public_numbers().n.to_bytes(256, byteorder='big')
    modulus_b64url = base64.urlsafe_b64encode(modulus_bytes).rstrip(b'=').decode()

    # Retrieves the public keys stored in the json file
    try:
        with open('public_key.json', 'r') as f:
            public_keys = json.load(f)
    except FileNotFoundError:
        pass

    # Calculates the key id for the public key
    key_id = f"key{len(public_keys) + 1}"

    # Calculates the expiry timestamp to be one day from when this function was called
    expiry_timestamp = (datetime.utcnow() + timedelta(days=1)).timestamp()

    # Dictionary to hold the key info of the public key
    key_info = {
        "kid": key_id,
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "n": modulus_b64url,
        "exp": expiry_timestamp
    }

    # Update the public_keys global variable to hold the new public key
    public_keys[key_id] = key_info

    # Redump the public keys back into the json file with the new one added
    with open('public_key.json', 'w') as f:
        json.dump(public_keys, f)

    # Precautionary load of the public keys
    public_keys = load_public_keys()

    # Returns both the private key and the key id for the public key
    return private_key, key_id

# Function to generate an expired RSA key pair
def generate_expired_rsa_key_pair():
    global public_keys
    # Generates a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Generates a public RSA key
    public_key = private_key.public_key()

    # Encodes the n value using base64url
    modulus_bytes = public_key.public_numbers().n.to_bytes(256, byteorder='big')
    modulus_b64url = base64.urlsafe_b64encode(modulus_bytes).rstrip(b'=').decode()
    
    # Loads all of the public keys
    try:
        with open('public_key.json', 'r') as f:
            public_keys = json.load(f)
    except FileNotFoundError:
        pass
    
    # Calculates the key id for the public key
    key_id = f"key{len(public_keys) + 1}"

    # Sets the expiry timestamp to a day previous to when it was created
    expiry_timestamp = (datetime.utcnow() - timedelta(days=1)).timestamp()

    # Sets the key info for the public key
    key_info = {
        "kid": key_id,
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "n": modulus_b64url,
        "exp": expiry_timestamp
    }

    # Updates the public keys with the new key
    public_keys[key_id] = key_info

    # Redumps all of the public keys
    with open('public_key.json', 'w') as f:
        json.dump(public_keys, f)

    # Precautionary load of the public keys
    public_keys = load_public_keys()

    # Returns the private key, key id and expiry timestamp
    return private_key, key_id, expiry_timestamp

# Route to retrieve JWKS
@app.route('/.well-known/jwks.json')
def get_jwks():
    # Calculates the current time
    current_time = datetime.utcnow().timestamp()
    # Creates the valid keys variable
    valid_keys = []
    # Loops through all of the keys stored in public_keys
    for kid, key_info in public_keys.items():
        # Gets what the expiry is of the key
        expiry = key_info["exp"] if "exp" in key_info else 0
        # Calculates whether the expiration timestap is past what the current time is
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
    # Make the JWKS variable
    jwks = {"keys": valid_keys}
    # Return the JWKS as a JSON Object
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
    
    #Returns the JWT token
    return token

if __name__ == '__main__':
    app.run(debug=True, port=8080)
