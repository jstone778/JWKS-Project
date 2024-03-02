import unittest
import requests

class TestFakeJWKS(unittest.TestCase):
    def test_get_jwks(self):
        response = requests.get('http://127.0.0.1:8080/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        # Check if the 'keys' key exists in the response
        self.assertIn('keys', jwks)
        keys = jwks['keys']
        # Ensure that at least one key is returned
        self.assertGreater(len(keys), 0)
        # Ensure that each key has the required attributes
        for key in keys:
            self.assertIn('kid', key)
            self.assertIn('alg', key)
            self.assertIn('kty', key)
            self.assertIn('use', key)
            self.assertIn('n', key)
            self.assertIn('exp', key)

    def test_auth(self):
        response = requests.post('http://localhost:8080/auth')
        self.assertEqual(response.status_code, 200)
        token = response.text
        # Ensure that a token is returned
        self.assertTrue(token)

    def test_auth_expired_key(self):
        headers = {'Content-Type': 'application/json'}
        params = {'expired': 'true'}
        response = requests.post('http://localhost:8080/auth', headers=headers, params=params)
        assert response.status_code == 200

    def test_auth_no_expired_param(self):
        headers = {'Content-Type': 'application/json'}
        response = requests.post('http://localhost:8080/auth', headers=headers)
        assert response.status_code == 200

    def test_get_jwks_with_expired_and_valid_keys(self):
        response = requests.get('http://localhost:8080/.well-known/jwks.json')
        jwks = response.json()
        assert len(jwks['keys']) > 0
        for key in jwks['keys']:
            assert 'kid' in key
            assert 'alg' in key
            assert 'kty' in key
            assert 'use' in key
            assert 'n' in key
            assert 'exp' in key

if __name__ == '__main__':
    unittest.main()

