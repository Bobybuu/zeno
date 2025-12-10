# payments/models.py
from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator

User = get_user_model()

class Payment(models.Model):
    PAYMENT_METHODS = (
        ('mpesa', 'M-Pesa'),
        ('card', 'Credit Card'),
        ('cash', 'Cash on Delivery'),
    )
    
    PAYMENT_STATUS = (
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    )
    
    order = models.OneToOneField('orders.Order', on_delete=models.CASCADE, related_name='payment')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    
    # Payment details
    amount = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    currency = models.CharField(max_length=3, default='KES')
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHODS, default='mpesa')
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default='pending')
    
    # M-Pesa specific fields
    mpesa_receipt_number = models.CharField(max_length=50, blank=True)
    phone_number = models.CharField(max_length=15)
    transaction_date = models.DateTimeField(null=True, blank=True)
    
    # Generic payment fields
    transaction_id = models.CharField(max_length=100, blank=True)
    payment_gateway_response = models.JSONField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Payment #{self.id} - {self.amount} {self.currency}"
    
    class Meta:
        ordering = ['-created_at']

class MpesaConfiguration(models.Model):
    """Store M-Pesa API configuration"""
    environment = models.CharField(max_length=10, choices=(
        ('sandbox', 'Sandbox'),
        ('production', 'Production'),
    ), default='sandbox')
    consumer_key = models.CharField(max_length=255)
    consumer_secret = models.CharField(max_length=255)
    shortcode = models.CharField(max_length=20)
    passkey = models.CharField(max_length=255)
    callback_url = models.URLField()
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"M-Pesa {self.environment} Configuration"
    
    class Meta:
        verbose_name_plural = "M-Pesa Configurations"