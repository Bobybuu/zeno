# test_cognito_full.py
import os
import sys
import boto3
import requests
from dotenv import load_dotenv
from botocore.exceptions import ClientError, NoCredentialsError

# Load environment variables
load_dotenv()

def test_environment():
    """Test if environment variables are set"""
    print("=" * 60)
    print("Environment Variables Test")
    print("=" * 60)
    
    required_vars = [
        ('AWS_ACCESS_KEY_ID', 'AWS Access Key ID'),
        ('AWS_SECRET_ACCESS_KEY', 'AWS Secret Access Key'),
        ('COGNITO_USER_POOL_ID', 'Cognito User Pool ID'),
        ('COGNITO_CLIENT_ID', 'Cognito Client ID'),
    ]
    
    optional_vars = [
        ('COGNITO_DOMAIN', 'Cognito Domain'),
        ('AWS_REGION', 'AWS Region'),
    ]
    
    all_valid = True
    
    # Check required
    print("\n🔍 REQUIRED VARIABLES:")
    for var, desc in required_vars:
        value = os.getenv(var)
        if value:
            masked = '*' * 8 + value[-4:] if 'SECRET' in var or 'KEY' in var else value
            print(f"  ✅ {desc}: {masked}")
        else:
            print(f"  ❌ {desc}: MISSING")
            all_valid = False
    
    # Check optional
    print("\n🔍 OPTIONAL VARIABLES:")
    for var, desc in optional_vars:
        value = os.getenv(var)
        if value:
            print(f"  ✅ {desc}: {value}")
        else:
            print(f"  ⚠️  {desc}: Not set (using default)")
    
    return all_valid

def test_aws_credentials():
    """Test AWS credentials"""
    print("\n" + "=" * 60)
    print("AWS Credentials Test")
    print("=" * 60)
    
    try:
        # Create STS client to test credentials
        sts = boto3.client(
            'sts',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=os.getenv('AWS_REGION', 'us-east-1')
        )
        
        identity = sts.get_caller_identity()
        print(f"✅ AWS Credentials are valid")
        print(f"   Account ID: {identity['Account']}")
        print(f"   User ID: {identity['UserId']}")
        print(f"   ARN: {identity['Arn']}")
        
        return True
    except NoCredentialsError:
        print("❌ No AWS credentials found")
        return False
    except ClientError as e:
        print(f"❌ AWS Credentials invalid: {e.response['Error']['Message']}")
        return False
    except Exception as e:
        print(f"❌ Error testing AWS credentials: {str(e)}")
        return False

def test_cognito_connection():
    """Test connection to Cognito User Pool"""
    print("\n" + "=" * 60)
    print("Cognito Connection Test")
    print("=" * 60)
    
    user_pool_id = os.getenv('COGNITO_USER_POOL_ID')
    client_id = os.getenv('COGNITO_CLIENT_ID')
    region = os.getenv('AWS_REGION', 'us-east-1')
    
    if not user_pool_id or not client_id:
        print("❌ Missing Cognito configuration")
        return False
    
    try:
        # Initialize Cognito client
        client = boto3.client(
            'cognito-idp',
            region_name=region,
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
        )
        
        # Test user pool connection
        response = client.describe_user_pool(UserPoolId=user_pool_id)
        print(f"✅ User Pool accessible: {response['UserPool']['Name']}")
        
        # Test app client
        response = client.describe_user_pool_client(
            UserPoolId=user_pool_id,
            ClientId=client_id
        )
        print(f"✅ App Client accessible: {response['UserPoolClient']['ClientName']}")
        
        # Check auth flows
        auth_flows = response['UserPoolClient'].get('ExplicitAuthFlows', [])
        print(f"✅ Auth flows configured: {len(auth_flows)} flows")
        
        # Print important settings
        print(f"\n📋 App Client Settings:")
        print(f"   Access Token Validity: {response['UserPoolClient'].get('AccessTokenValidity', 'N/A')} minutes")
        print(f"   Refresh Token Validity: {response['UserPoolClient'].get('RefreshTokenValidity', 'N/A')} days")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"❌ Cognito connection failed: {error_code} - {error_message}")
        return False
    except Exception as e:
        print(f"❌ Error connecting to Cognito: {str(e)}")
        return False

def test_domain():
    """Test Cognito domain accessibility"""
    print("\n" + "=" * 60)
    print("Cognito Domain Test")
    print("=" * 60)
    
    domain = os.getenv('COGNITO_DOMAIN')
    if not domain:
        print("⚠️  No domain configured in environment")
        return False
    
    try:
        # Test login page
        response = requests.get(f'https://{domain}/login', timeout=10)
        print(f"✅ Domain accessible: HTTP {response.status_code}")
        
        # Test OAuth endpoints
        endpoints = ['/oauth2/authorize', '/oauth2/token', '/oauth2/userInfo']
        for endpoint in endpoints:
            url = f'https://{domain}{endpoint}'
            try:
                response = requests.head(url, timeout=5)
                print(f"✅ {endpoint}: HTTP {response.status_code}")
            except:
                print(f"⚠️  {endpoint}: Not accessible")
        
        return True
        
    except requests.exceptions.Timeout:
        print(f"❌ Domain timeout: {domain}")
        return False
    except Exception as e:
        print(f"❌ Domain error: {str(e)}")
        return False

def test_jwks():
    """Test JWKS configuration"""
    print("\n" + "=" * 60)
    print("JWKS Configuration Test")
    print("=" * 60)
    
    user_pool_id = os.getenv('COGNITO_USER_POOL_ID')
    region = os.getenv('AWS_REGION', 'us-east-1')
    
    if not user_pool_id:
        print("❌ No User Pool ID configured")
        return False
    
    try:
        jwks_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'
        response = requests.get(jwks_url, timeout=10)
        
        if response.status_code == 200:
            jwks_data = response.json()
            keys = jwks_data.get('keys', [])
            print(f"✅ JWKS accessible: {len(keys)} signing keys found")
            
            # Check for RSA keys (Cognito uses RS256)
            rsa_keys = [k for k in keys if k.get('kty') == 'RSA']
            print(f"   RSA keys: {len(rsa_keys)}")
            
            return True
        else:
            print(f"❌ JWKS returned HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ JWKS error: {str(e)}")
        return False

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("AWS COGNITO FULL INTEGRATION TEST")
    print("=" * 60)
    
    tests = [
        ("Environment Variables", test_environment),
        ("AWS Credentials", test_aws_credentials),
        ("Cognito Connection", test_cognito_connection),
        ("Domain Accessibility", test_domain),
        ("JWKS Configuration", test_jwks),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n▶️  Running: {test_name}")
        print("-" * 40)
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ Test crashed: {str(e)}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
        if success:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Cognito is properly configured.")
    else:
        print(f"\n⚠️  {total - passed} tests failed. Check configuration.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)