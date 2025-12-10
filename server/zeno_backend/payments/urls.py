# payments/urls.py
from django.urls import path, include
from .views import initiate_payment, mpesa_callback, payment_status, retry_payment
from .views import PaymentViewSet
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'payments', PaymentViewSet, basename='payment')  # Add basename

urlpatterns = [
    path('', include(router.urls)),
    path('initiate-payment/', initiate_payment, name='initiate-payment'),
    path('mpesa-callback/', mpesa_callback, name='mpesa-callback'),
    path('payment-status/<int:payment_id>/', payment_status, name='payment-status'),
    path('retry-payment/<int:payment_id>/', retry_payment, name='retry-payment'),
]