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
import sqlite3

# Function to serialize private key to PKCS1 PEM format
def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

# Function to deserialize private key from PKCS1 PEM format
def deserialize_private_key(serialized_key):
    return serialization.load_pem_private_key(serialized_key, password=None, backend=default_backend())

conn = sqlite3.connect('totally_not_my_privateKeys.db', check_same_thread=False)

cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)''')

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

    # Serialize private key to PKCS1 PEM format
    serialized_private_key = serialize_private_key(private_key)

    # Retrieves the public keys stored in the json file
    try:
        with open('public_key.json', 'r') as f:
            public_keys = json.load(f)
    except FileNotFoundError:
        pass

    # Calculates the key id for the public key
    key_id = f"key{len(public_keys) + 1}"

    # Calculates the expiry timestamp to be one day from when this function was called
    expiry_timestamp = int((datetime.utcnow() + timedelta(days=1)).timestamp())

    # Insert private key and expiry into the database
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialized_private_key.decode(), int(expiry_timestamp)))
    conn.commit()

    # Precautionary load of the public keys
    public_keys = load_public_keys()

    # Returns both the private key and the key id for the public key
    return private_key, key_id

# Function to generate an expired RSA key pair
def generate_expired_rsa_key_pair():
    # Connect to the SQLite database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    global public_keys
    # Generates a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize private key to PKCS1 PEM format
    serialized_private_key = serialize_private_key(private_key)
    
    # Loads all of the public keys
    try:
        with open('public_key.json', 'r') as f:
            public_keys = json.load(f)
    except FileNotFoundError:
        pass
    
    # Calculates the key id for the public key
    key_id = f"key{len(public_keys) + 1}"

    # Sets the expiry timestamp to a day previous to when it was created
    expiry_timestamp = int((datetime.utcnow() - timedelta(days=1)).timestamp())

    # Insert private key and expiry into the database
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialized_private_key.decode(), int(expiry_timestamp)))
    conn.commit()

    conn.close()


    # Precautionary load of the public keys
    public_keys = load_public_keys()

    # Returns the private key, key id and expiry timestamp
    return private_key, key_id, expiry_timestamp

def check_and_initialize_keys():
    # Connect to the SQLite database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()

    # Check if there are any rows in the keys table
    cursor.execute("SELECT COUNT(*) FROM keys")
    row_count = cursor.fetchone()[0]

    if row_count == 0:
        # Database is empty, generate key pairs
        expired_private_key, expired_key_id, expired_expiry = generate_expired_rsa_key_pair()
        private_key, key_id = generate_rsa_key_pair()

        # Insert expired key into the database
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialize_private_key(expired_private_key).decode(), expired_expiry))

        # Insert non-expired key into the database
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialize_private_key(private_key).decode(), (datetime.utcnow() + timedelta(days=1)).timestamp()))

        # Commit the transaction
        conn.commit()

    # Close the database connection
    conn.close()

# Call the function to check and initialize keys if needed
check_and_initialize_keys()


# Route to retrieve JWKS
@app.route('/.well-known/jwks.json')
def get_jwks():
    # Calculate the current time
    current_time = datetime.utcnow().timestamp()

    # Retrieve all valid (non-expired) private keys from the database
    cursor.execute("SELECT key FROM keys WHERE exp >= ?", (current_time,))
    valid_private_keys = [deserialize_private_key(row[0].encode()) for row in cursor.fetchall()]

    # Create the JWKS response from the valid private keys
    jwks = {
        "keys": [{
            "kid": f"key{i + 1}",
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "n": base64.urlsafe_b64encode(key.public_key().public_numbers().n.to_bytes(256, byteorder='big')).decode().rstrip('='),
            "e": "AQAB"
        } for i, key in enumerate(valid_private_keys)]
    }

    # Return the JWKS as a JSON Object
    return jsonify(jwks)


# Route for authentication
@app.route('/auth', methods=['POST'])
def auth():
    # Check if the 'expired' query parameter is present
    expired = request.args.get('expired') == 'true'
    check_and_initialize_keys()
    if expired:
        # Read an expired key from the database
        cursor.execute("SELECT key FROM keys WHERE exp < ?", (datetime.utcnow().timestamp(),))
        row = cursor.fetchone()
        if row:
            # Deserialize the private key
            private_key = deserialize_private_key(row[0].encode())

            # Generate JWT using the expired key
            # Assuming private_key is an instance of RSAPrivateKey
            token = jwt.encode({'username': 'userABC', 'password': 'password123'}, private_key, algorithm='RS256', headers={"kid": "key1"})
        else:
            token = "Expired key not found"
    else:
        # Read a valid (unexpired) key from the database
        cursor.execute("SELECT key FROM keys WHERE exp >= ?", (datetime.utcnow().timestamp(),))
        row = cursor.fetchone()
        if row:
            # Deserialize the private key
            private_key = deserialize_private_key(row[0].encode())

            # Generate JWT using the valid key
            token = jwt.encode({'username': 'userABC', 'password': 'password123'}, private_key, algorithm='RS256', headers={"kid": "key1"})
        else:
            token = "Valid key not found"

    # Returns the JWT token or an error message
    return token


if __name__ == '__main__':
    app.run(debug=True, port=8080)
    conn.close()
