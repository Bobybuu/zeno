# payments/serializers.py
from rest_framework import serializers
from .models import Payment, MpesaConfiguration

class PaymentSerializer(serializers.ModelSerializer):
    order_id = serializers.IntegerField(source='order.id', read_only=True)
    service_name = serializers.CharField(source='order.service.name', read_only=True)
    vendor_name = serializers.CharField(source='order.vendor.business_name', read_only=True)
    
    class Meta:
        model = Payment
        fields = [
            'id', 'order', 'order_id', 'service_name', 'vendor_name', 'amount', 'currency',
            'payment_method', 'status', 'mpesa_receipt_number', 'phone_number',
            'transaction_date', 'transaction_id', 'created_at', 'updated_at'
        ]
        read_only_fields = ['order', 'amount', 'currency', 'created_at', 'updated_at']

class InitiatePaymentSerializer(serializers.Serializer):
    order_id = serializers.IntegerField()
    phone_number = serializers.CharField(max_length=15)
    payment_method = serializers.ChoiceField(choices=Payment.PAYMENT_METHODS, default='mpesa')

class MpesaCallbackSerializer(serializers.Serializer):
    """Serializer for M-Pesa callback data"""
    Body = serializers.DictField()
    
    def validate(self, data):
        stk_callback = data.get('Body', {}).get('stkCallback', {})
        if not stk_callback:
            raise serializers.ValidationError("Invalid M-Pesa callback format")
        return data

class MpesaConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = MpesaConfiguration
        fields = ['id', 'environment', 'shortcode', 'callback_url', 'is_active']
        read_only_fields = ['consumer_key', 'consumer_secret', 'passkey']