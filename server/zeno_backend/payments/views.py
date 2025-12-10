# payments/views.py
import requests
import json
import base64  # Add this import
from datetime import datetime
from django.conf import settings
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action, api_view, permission_classes  # Add permission_classes import
from rest_framework.response import Response
from django.utils import timezone
from .models import Payment, MpesaConfiguration
from orders.models import Order
from .serializers import PaymentSerializer, InitiatePaymentSerializer, MpesaCallbackSerializer

class PaymentViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = PaymentSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return Payment.objects.filter(user=self.request.user)
    @property
    def queryset(self):
        return self.get_queryset()

class MpesaService:
    def __init__(self):
        try:
            self.config = MpesaConfiguration.objects.get(is_active=True)
        except MpesaConfiguration.DoesNotExist:
            raise Exception("M-Pesa configuration not found")
    
    def get_access_token(self):
        """Get M-Pesa access token"""
        auth_url = f"https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        if self.config.environment == 'production':
            auth_url = f"https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        
        response = requests.get(
            auth_url,
            auth=(self.config.consumer_key, self.config.consumer_secret)
        )
        
        if response.status_code == 200:
            return response.json()['access_token']
        else:
            raise Exception(f"Failed to get access token: {response.text}")
    
    def initiate_stk_push(self, phone_number, amount, order_id):
        """Initiate STK push payment"""
        access_token = self.get_access_token()
        
        # Format phone number (remove + and any spaces)
        phone_number = phone_number.replace('+', '').replace(' ', '')
        if not phone_number.startswith('254'):
            if phone_number.startswith('0'):
                phone_number = '254' + phone_number[1:]
            else:
                phone_number = '254' + phone_number
        
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        password = base64.b64encode(
            f"{self.config.shortcode}{self.config.passkey}{timestamp}".encode()
        ).decode()
        
        payload = {
            "BusinessShortCode": self.config.shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(amount),
            "PartyA": phone_number,
            "PartyB": self.config.shortcode,
            "PhoneNumber": phone_number,
            "CallBackURL": self.config.callback_url,
            "AccountReference": f"ORDER{order_id}",
            "TransactionDesc": f"Payment for order #{order_id}"
        }
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        stk_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        if self.config.environment == 'production':
            stk_url = "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        
        response = requests.post(stk_url, json=payload, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"STK push failed: {response.text}")

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def initiate_payment(request):
    """Initiate payment for an order"""
    serializer = InitiatePaymentSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    order_id = serializer.validated_data['order_id']
    phone_number = serializer.validated_data['phone_number']
    payment_method = serializer.validated_data['payment_method']
    
    try:
        order = Order.objects.get(id=order_id, customer=request.user)
    except Order.DoesNotExist:
        return Response(
            {'error': 'Order not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Check if payment already exists
    if hasattr(order, 'payment'):
        return Response(
            {'error': 'Payment already initiated for this order'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Create payment record
    payment = Payment.objects.create(
        order=order,
        user=request.user,
        amount=order.total_amount,
        payment_method=payment_method,
        phone_number=phone_number
    )
    
    # Process M-Pesa payment
    if payment_method == 'mpesa':
        try:
            mpesa_service = MpesaService()
            stk_response = mpesa_service.initiate_stk_push(
                phone_number, order.total_amount, order.id
            )
            
            # Update payment with STK response
            payment.transaction_id = stk_response.get('CheckoutRequestID')
            payment.status = 'processing'
            payment.save()
            
            return Response({
                'message': 'M-Pesa payment initiated successfully',
                'checkout_request_id': stk_response.get('CheckoutRequestID'),
                'payment_id': payment.id
            })
            
        except Exception as e:
            payment.status = 'failed'
            payment.save()
            return Response(
                {'error': f'Failed to initiate payment: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    return Response(PaymentSerializer(payment).data)

@api_view(['POST'])
@permission_classes([])  # No authentication required for M-Pesa callbacks
def mpesa_callback(request):
    """Handle M-Pesa callback"""
    serializer = MpesaCallbackSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    
    callback_data = serializer.validated_data['Body']['stkCallback']
    checkout_request_id = callback_data['CheckoutRequestID']
    result_code = callback_data['ResultCode']
    
    try:
        payment = Payment.objects.get(transaction_id=checkout_request_id)
    except Payment.DoesNotExist:
        return Response({'error': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if result_code == 0:
        # Payment successful
        payment.status = 'completed'
        
        # Extract M-Pesa receipt number from callback metadata
        callback_metadata = callback_data.get('CallbackMetadata', {})
        items = callback_metadata.get('Item', [])
        for item in items:
            if item.get('Name') == 'MpesaReceiptNumber':
                payment.mpesa_receipt_number = item.get('Value', '')
                break
        
        payment.transaction_date = timezone.now()
        payment.payment_gateway_response = callback_data
        
        # Update order status
        payment.order.payment_status = 'paid'
        payment.order.save()
        
    else:
        # Payment failed
        payment.status = 'failed'
        payment.payment_gateway_response = callback_data
    
    payment.save()
    
    return Response({'message': 'Callback processed successfully'})

# Additional payment views
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def payment_status(request, payment_id):
    """Check payment status"""
    try:
        payment = Payment.objects.get(id=payment_id, user=request.user)
        serializer = PaymentSerializer(payment)
        return Response(serializer.data)
    except Payment.DoesNotExist:
        return Response(
            {'error': 'Payment not found'},
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def retry_payment(request, payment_id):
    """Retry a failed payment"""
    try:
        payment = Payment.objects.get(id=payment_id, user=request.user)
        
        if payment.status != 'failed':
            return Response(
                {'error': 'Can only retry failed payments'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Reset payment status and retry
        payment.status = 'pending'
        payment.transaction_id = ''
        payment.mpesa_receipt_number = ''
        payment.save()
        
        # Re-initiate payment
        return initiate_payment(request._request)  # Pass the original request
        
    except Payment.DoesNotExist:
        return Response(
            {'error': 'Payment not found'},
            status=status.HTTP_404_NOT_FOUND
        )