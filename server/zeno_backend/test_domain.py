# test_domain.py
import requests

DOMAIN = 'https://us-east-16qjqed9ep.auth.us-east-1.amazoncognito.com'
CLIENT_ID = '3oem04p3sgg0bvrntgaot32vd'

# Test if domain is accessible
try:
    response = requests.get(f'https://{DOMAIN}/login', timeout=5)
    print(f"✅ Domain accessible: {response.status_code}")
except Exception as e:
    print(f"❌ Domain not accessible: {e}")

# Test .well-known configuration
try:
    jwks_url = f'https://cognito-idp.us-east-1.amazonaws.com/us-east-1_6qJqed9EP/.well-known/jwks.json'
    response = requests.get(jwks_url)
    print(f"✅ JWKS configuration accessible: {response.status_code}")
except Exception as e:
    print(f"❌ JWKS not accessible: {e}")