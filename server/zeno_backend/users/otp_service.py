import boto3
from django.conf import settings
from botocore.exceptions import ClientError

class AWSSNSService:
    def __init__(self):
        self.client = boto3.client(
            'sns',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_SNS_REGION  # e.g., 'us-east-1'
        )
    
    def send_otp(self, phone_number, otp):
        try:
            # Format phone number to E.164 format
            formatted_number = self._format_phone_number(phone_number)
            
            message = f"Your Zeno verification code is: {otp}. This code expires in 10 minutes."
            
            response = self.client.publish(
                PhoneNumber=formatted_number,
                Message=message,
                MessageAttributes={
                    'AWS.SNS.SMS.SenderID': {
                        'DataType': 'String',
                        'StringValue': 'ZenoApp'
                    },
                    'AWS.SNS.SMS.SMSType': {
                        'DataType': 'String', 
                        'StringValue': 'Transactional'  # Lower cost for OTPs
                    }
                }
            )
            print(f"AWS SNS Response: {response}")
            return True
            
        except ClientError as e:
            print(f"AWS SNS Error: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error: {e}")
            return False
    
    def _format_phone_number(self, phone_number):
        """Format phone number to E.164 format required by AWS SNS"""
        # Remove any non-digit characters
        cleaned = ''.join(filter(str.isdigit, phone_number))
        
        # Handle Kenyan phone numbers specifically
        if cleaned.startswith('254') and len(cleaned) == 12:
            # Already has Kenya country code without +
            return f"+{cleaned}"
        elif cleaned.startswith('0') and len(cleaned) == 10:
            # Kenyan number starting with 0 (07XX, 01XX) - remove 0, add +254
            return f"+254{cleaned[1:]}"
        elif len(cleaned) == 9:
            # Kenyan number without leading 0 (7XX, 1XX) - add +254
            return f"+254{cleaned}"
        elif cleaned.startswith('+254') and len(cleaned) == 13:
            # Already properly formatted Kenyan number
            return cleaned
        elif cleaned.startswith('1') and len(cleaned) == 11:
            # US numbers
            return f"+{cleaned}"
        elif len(cleaned) == 10 and not cleaned.startswith('0'):
            # Assume US number without country code
            return f"+1{cleaned}"
        elif not cleaned.startswith('+'):
            # Default to Kenya for any other number without country code
            if cleaned.startswith('0') and len(cleaned) == 10:
                return f"+254{cleaned[1:]}"
            elif len(cleaned) == 9:
                return f"+254{cleaned}"
            else:
                return f"+254{cleaned}"  # Fallback to Kenya
        
        return cleaned

# Keep your development fallback
class DevelopmentOTPService:
    def send_otp(self, phone_number, otp):
        print(f"DEV OTP for {phone_number}: {otp}")
        return True

# Factory function to choose service
def get_otp_service():
    if settings.DEBUG and not all([
        settings.AWS_ACCESS_KEY_ID,
        settings.AWS_SECRET_ACCESS_KEY
    ]):
        return DevelopmentOTPService()
    return AWSSNSService()