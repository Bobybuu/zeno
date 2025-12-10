# services/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ServiceCategoryViewSet, ServiceViewSet

router = DefaultRouter()
router.register(r'categories', ServiceCategoryViewSet)
router.register(r'services', ServiceViewSet)


urlpatterns = [
    path('', include(router.urls)),
    path('mapbox-config/', ServiceViewSet.mapbox_config, name='mapbox-config'),
]