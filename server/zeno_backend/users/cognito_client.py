"""
AWS Cognito client for Zeno Application
"""

import boto3
import logging
from django.conf import settings
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class CognitoClient:
    """
    Client for interacting with AWS Cognito
    """
    
    def __init__(self):
        self.client = boto3.client(
            'cognito-idp',
            region_name=settings.AWS_REGION,
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY
        )
        self.client_id = settings.COGNITO_CLIENT_ID
        self.user_pool_id = settings.COGNITO_USER_POOL_ID
    
    def register_user(self, email, password, first_name='', last_name='', phone_number=''):
        """
        Register a new user in Cognito
        """
        try:
            response = self.client.sign_up(
                ClientId=self.client_id,
                Username=email,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'given_name', 'Value': first_name},
                    {'Name': 'family_name', 'Value': last_name},
                    {'Name': 'phone_number', 'Value': phone_number} if phone_number else 
                    {'Name': 'phone_number', 'Value': ''},
                ]
            )
            
            logger.info(f"User registered in Cognito: {email}")
            return response
            
        except ClientError as e:
            logger.error(f"Cognito registration failed: {str(e)}")
            raise
    
    def verify_email(self, email, verification_code):
        """
        Verify user email with code
        """
        try:
            response = self.client.confirm_sign_up(
                ClientId=self.client_id,
                Username=email,
                ConfirmationCode=verification_code
            )
            
            logger.info(f"Email verified in Cognito: {email}")
            return response
            
        except ClientError as e:
            logger.error(f"Cognito email verification failed: {str(e)}")
            raise
    
    def resend_verification_email(self, email):
        """
        Resend verification email
        """
        try:
            response = self.client.resend_confirmation_code(
                ClientId=self.client_id,
                Username=email
            )
            
            logger.info(f"Verification email resent: {email}")
            return response
            
        except ClientError as e:
            logger.error(f"Failed to resend verification email: {str(e)}")
            raise
    
    def initiate_password_reset(self, email):
        """
        Initiate password reset
        """
        try:
            response = self.client.forgot_password(
                ClientId=self.client_id,
                Username=email
            )
            
            logger.info(f"Password reset initiated: {email}")
            return response
            
        except ClientError as e:
            logger.error(f"Password reset initiation failed: {str(e)}")
            raise
    
    def confirm_password_reset(self, email, verification_code, new_password):
        """
        Confirm password reset with verification code
        """
        try:
            response = self.client.confirm_forgot_password(
                ClientId=self.client_id,
                Username=email,
                ConfirmationCode=verification_code,
                Password=new_password
            )
            
            logger.info(f"Password reset confirmed: {email}")
            return response
            
        except ClientError as e:
            logger.error(f"Password reset confirmation failed: {str(e)}")
            raise
    
    def change_password(self, email, current_password, new_password):
        """
        Change user password
        """
        try:
            # First authenticate to get access token
            auth_response = self.client.initiate_auth(
                ClientId=self.client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': current_password
                }
            )
            
            access_token = auth_response['AuthenticationResult']['AccessToken']
            
            # Change password
            response = self.client.change_password(
                PreviousPassword=current_password,
                ProposedPassword=new_password,
                AccessToken=access_token
            )
            
            logger.info(f"Password changed: {email}")
            return response
            
        except ClientError as e:
            logger.error(f"Password change failed: {str(e)}")
            raise
    
    def get_user(self, email):
        """
        Get user details from Cognito
        """
        try:
            response = self.client.admin_get_user(
                UserPoolId=self.user_pool_id,
                Username=email
            )
            
            return response
            
        except ClientError as e:
            logger.error(f"Failed to get user from Cognito: {str(e)}")
            raise
    
    def update_user_attributes(self, email, attributes):
        """
        Update user attributes in Cognito
        """
        try:
            response = self.client.admin_update_user_attributes(
                UserPoolId=self.user_pool_id,
                Username=email,
                UserAttributes=attributes
            )
            
            logger.info(f"User attributes updated: {email}")
            return response
            
        except ClientError as e:
            logger.error(f"Failed to update user attributes: {str(e)}")
            raise
    
    def delete_user(self, email):
        """
        Delete user from Cognito
        """
        try:
            response = self.client.admin_delete_user(
                UserPoolId=self.user_pool_id,
                Username=email
            )
            
            logger.info(f"User deleted from Cognito: {email}")
            return response
            
        except ClientError as e:
            logger.error(f"Failed to delete user from Cognito: {str(e)}")
            raise