# vendors/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Create a router and register our viewsets
router = DefaultRouter()
router.register(r'vendors', views.VendorViewSet, basename='vendor')
router.register(r'reviews', views.VendorReviewViewSet, basename='vendor-review')
router.register(r'gas-products', views.GasProductViewSet, basename='gas-product')
router.register(r'product-images', views.GasProductImageViewSet, basename='product-image')
router.register(r'operating-hours', views.OperatingHoursViewSet, basename='operating-hours')

# The URL patterns are now determined automatically by the router
urlpatterns = [
    path('', include(router.urls)),
]