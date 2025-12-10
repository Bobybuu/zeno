"""
Custom validators for Zeno Application
"""

import re
import phonenumbers
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.utils.deconstruct import deconstructible


@deconstructible
class PhoneNumberValidator:
    """
    Validates phone numbers using phonenumbers library
    Supports international formats
    """
    default_region = 'KE'  # Default to Kenya
    
    def __init__(self, region=None):
        self.region = region or self.default_region
    
    def __call__(self, value):
        if not value:
            return
        
        try:
            # Remove any whitespace
            value = value.strip()
            
            # Parse the phone number
            parsed_number = phonenumbers.parse(value, self.region)
            
            # Check if the number is valid
            if not phonenumbers.is_valid_number(parsed_number):
                raise ValidationError(
                    _('%(value)s is not a valid phone number'),
                    params={'value': value},
                    code='invalid_phone'
                )
            
            # Check if the number is possible
            if not phonenumbers.is_possible_number(parsed_number):
                raise ValidationError(
                    _('%(value)s is not a possible phone number'),
                    params={'value': value},
                    code='impossible_phone'
                )
            
            # Format to E.164 format for storage consistency
            formatted = phonenumbers.format_number(
                parsed_number,
                phonenumbers.PhoneNumberFormat.E164
            )
            
            # Return formatted number if validation passes
            return formatted
            
        except phonenumbers.NumberParseException as e:
            raise ValidationError(
                _('%(value)s could not be parsed as a phone number: %(error)s'),
                params={'value': value, 'error': str(e)},
                code='parse_error'
            )
    
    def __eq__(self, other):
        return (
            isinstance(other, PhoneNumberValidator) and
            self.region == other.region
        )


@deconstructible
class CoordinatesValidator:
    """
    Validates latitude and longitude coordinates
    """
    
    def __call__(self, value):
        if value is None:
            return
        
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise ValidationError(
                _('Coordinates must be a number'),
                code='invalid_coordinate'
            )
    
    def validate_latitude(self, value):
        """Validate latitude range (-90 to 90)"""
        if value is None:
            return
        
        try:
            lat = float(value)
            if not (-90 <= lat <= 90):
                raise ValidationError(
                    _('Latitude must be between -90 and 90 degrees'),
                    code='invalid_latitude'
                )
        except (TypeError, ValueError):
            raise ValidationError(
                _('Latitude must be a number'),
                code='invalid_latitude'
            )
    
    def validate_longitude(self, value):
        """Validate longitude range (-180 to 180)"""
        if value is None:
            return
        
        try:
            lng = float(value)
            if not (-180 <= lng <= 180):
                raise ValidationError(
                    _('Longitude must be between -180 and 180 degrees'),
                    code='invalid_longitude'
                )
        except (TypeError, ValueError):
            raise ValidationError(
                _('Longitude must be a number'),
                code='invalid_longitude'
            )
    
    def __eq__(self, other):
        return isinstance(other, CoordinatesValidator)


@deconstructible
class PasswordValidator:
    """
    Validates password strength
    """
    
    def __init__(self, min_length=8, require_digit=True, require_uppercase=True, 
                 require_lowercase=True, require_special=True):
        self.min_length = min_length
        self.require_digit = require_digit
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_special = require_special
    
    def __call__(self, value):
        errors = []
        
        # Check minimum length
        if len(value) < self.min_length:
            errors.append(
                ValidationError(
                    _(f'Password must be at least {self.min_length} characters long'),
                    code='password_too_short'
                )
            )
        
        # Check for digit
        if self.require_digit and not any(char.isdigit() for char in value):
            errors.append(
                ValidationError(
                    _('Password must contain at least one digit'),
                    code='password_no_digit'
                )
            )
        
        # Check for uppercase
        if self.require_uppercase and not any(char.isupper() for char in value):
            errors.append(
                ValidationError(
                    _('Password must contain at least one uppercase letter'),
                    code='password_no_uppercase'
                )
            )
        
        # Check for lowercase
        if self.require_lowercase and not any(char.islower() for char in value):
            errors.append(
                ValidationError(
                    _('Password must contain at least one lowercase letter'),
                    code='password_no_lowercase'
                )
            )
        
        # Check for special characters
        if self.require_special and not any(not char.isalnum() for char in value):
            errors.append(
                ValidationError(
                    _('Password must contain at least one special character'),
                    code='password_no_special'
                )
            )
        
        if errors:
            raise ValidationError(errors)
    
    def __eq__(self, other):
        return (
            isinstance(other, PasswordValidator) and
            self.min_length == other.min_length and
            self.require_digit == other.require_digit and
            self.require_uppercase == other.require_upper and
            self.require_lowercase == other.require_lower and
            self.require_special == other.require_special
        )


@deconstructible
class KenyanIDValidator:
    """
    Validates Kenyan National ID format
    """
    
    def __call__(self, value):
        if not value:
            return
        
        # Remove any spaces or dashes
        value = value.strip().replace(' ', '').replace('-', '')
        
        # Kenyan ID should be 8 digits
        if not value.isdigit():
            raise ValidationError(
                _('National ID must contain only digits'),
                code='invalid_id_format'
            )
        
        if len(value) != 8:
            raise ValidationError(
                _('National ID must be exactly 8 digits'),
                code='invalid_id_length'
            )
        
        # Simple checksum validation (Luhn algorithm)
        if not self._luhn_checksum(value):
            raise ValidationError(
                _('Invalid National ID number'),
                code='invalid_id_checksum'
            )
    
    def _luhn_checksum(self, card_number):
        """Luhn algorithm for checksum validation"""
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        
        for d in even_digits:
            checksum += sum(digits_of(d * 2))
        
        return checksum % 10 == 0
    
    def __eq__(self, other):
        return isinstance(other, KenyanIDValidator)


@deconstructible
class BusinessRegistrationNumberValidator:
    """
    Validates business registration numbers
    """
    
    def __call__(self, value):
        if not value:
            return
        
        value = value.strip().upper()
        
        # Common patterns for business registration numbers
        patterns = [
            r'^CPR/\d{4}/\d{5}$',  # Kenya: CPR/2020/12345
            r'^BN/\d{9}$',         # Alternative format
            r'^\d{6,10}$',         # Simple numeric
        ]
        
        if not any(re.match(pattern, value) for pattern in patterns):
            raise ValidationError(
                _('Invalid business registration number format'),
                code='invalid_business_reg'
            )
    
    def __eq__(self, other):
        return isinstance(other, BusinessRegistrationNumberValidator)


@deconstructible
class KenyanPostalCodeValidator:
    """
    Validates Kenyan postal codes
    """
    
    def __call__(self, value):
        if not value:
            return
        
        value = value.strip()
        
        # Kenyan postal codes are typically 5 digits
        if not re.match(r'^\d{5}$', value):
            raise ValidationError(
                _('Postal code must be 5 digits'),
                code='invalid_postal_code'
            )
        
        # First two digits should be between 00 and 99
        first_two = int(value[:2])
        if not (0 <= first_two <= 99):
            raise ValidationError(
                _('Invalid postal code format'),
                code='invalid_postal_code_format'
            )
    
    def __eq__(self, other):
        return isinstance(other, KenyanPostalCodeValidator)


@deconstructible
class ImageFileValidator:
    """
    Validates image file uploads
    """
    
    def __init__(self, max_size_mb=5, allowed_extensions=None):
        self.max_size_bytes = max_size_mb * 1024 * 1024
        
        if allowed_extensions is None:
            self.allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
        else:
            self.allowed_extensions = allowed_extensions
    
    def __call__(self, value):
        import os
        
        # Check file size
        if value.size > self.max_size_bytes:
            raise ValidationError(
                _(f'File size must not exceed {self.max_size_bytes // (1024*1024)}MB'),
                code='file_too_large'
            )
        
        # Check file extension
        ext = os.path.splitext(value.name)[1].lower()
        if ext not in self.allowed_extensions:
            raise ValidationError(
                _(f'File type not allowed. Allowed types: {", ".join(self.allowed_extensions)}'),
                code='invalid_file_type'
            )
        
        # Check if file is actually an image
        from PIL import Image
        try:
            with Image.open(value) as img:
                img.verify()
        except Exception:
            raise ValidationError(
                _('Invalid image file'),
                code='invalid_image'
            )
    
    def __eq__(self, other):
        return (
            isinstance(other, ImageFileValidator) and
            self.max_size_bytes == other.max_size_bytes and
            set(self.allowed_extensions) == set(other.allowed_extensions)
        )


@deconstructible
class OpeningHoursValidator:
    """
    Validates opening hours JSON structure
    """
    
    def __call__(self, value):
        if not isinstance(value, dict):
            raise ValidationError(
                _('Opening hours must be a dictionary'),
                code='invalid_opening_hours'
            )
        
        days_of_week = ['monday', 'tuesday', 'wednesday', 'thursday', 
                       'friday', 'saturday', 'sunday']
        
        for day, hours in value.items():
            # Check day name
            if day.lower() not in days_of_week:
                raise ValidationError(
                    _(f'Invalid day: {day}. Must be one of {", ".join(days_of_week)}'),
                    code='invalid_day'
                )
            
            # Check hours structure
            if not isinstance(hours, dict):
                raise ValidationError(
                    _(f'Hours for {day} must be a dictionary'),
                    code='invalid_hours_structure'
                )
            
            # Check if open/close keys exist
            if 'open' not in hours:
                raise ValidationError(
                    _(f'Missing "open" key for {day}'),
                    code='missing_open_key'
                )
            
            if hours['open']:
                if 'open_time' not in hours:
                    raise ValidationError(
                        _(f'Missing "open_time" for {day}'),
                        code='missing_open_time'
                    )
                
                if 'close_time' not in hours:
                    raise ValidationError(
                        _(f'Missing "close_time" for {day}'),
                        code='missing_close_time'
                    )
                
                # Validate time format (HH:MM)
                time_pattern = r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$'
                if not re.match(time_pattern, hours['open_time']):
                    raise ValidationError(
                        _(f'Invalid open_time format for {day}. Use HH:MM'),
                        code='invalid_time_format'
                    )
                
                if not re.match(time_pattern, hours['close_time']):
                    raise ValidationError(
                        _(f'Invalid close_time format for {day}. Use HH:MM'),
                        code='invalid_time_format'
                    )
                
                # Check that close time is after open time
                from datetime import datetime
                open_time = datetime.strptime(hours['open_time'], '%H:%M').time()
                close_time = datetime.strptime(hours['close_time'], '%H:%M').time()
                
                if close_time <= open_time:
                    raise ValidationError(
                        _(f'Close time must be after open time for {day}'),
                        code='invalid_time_range'
                    )
    
    def __eq__(self, other):
        return isinstance(other, OpeningHoursValidator)


# Convenience validators
validate_phone_number = PhoneNumberValidator()
validate_coordinates = CoordinatesValidator()
validate_password = PasswordValidator()
validate_kenyan_id = KenyanIDValidator()
validate_business_reg = BusinessRegistrationNumberValidator()
validate_postal_code = KenyanPostalCodeValidator()
validate_image_file = ImageFileValidator()
validate_opening_hours = OpeningHoursValidator()