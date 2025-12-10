# services/views.py
from django.http import JsonResponse
from django.conf import settings
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Q
from .models import ServiceCategory, Service
from .serializers import ServiceCategorySerializer, ServiceSerializer, ServiceCreateSerializer

class ServiceCategoryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ServiceCategory.objects.all()
    serializer_class = ServiceCategorySerializer

class ServiceViewSet(viewsets.ModelViewSet):
    queryset = Service.objects.filter(available=True).select_related('vendor', 'category')
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['category__name', 'vendor__business_type']
    search_fields = ['name', 'description', 'vendor__business_name']
    ordering_fields = ['price', 'created_at', 'vendor__average_rating']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return ServiceCreateSerializer
        return ServiceSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by location proximity if coordinates provided
        lat = self.request.query_params.get('lat')
        lng = self.request.query_params.get('lng')
        radius = self.request.query_params.get('radius', 10)  # Default 10km
        
        if lat and lng:
            # Simple bounding box filter (for production, use PostGIS or geopy)
            try:
                lat = float(lat)
                lng = float(lng)
                radius = float(radius)
                
                # Approximate conversion: 1 degree ≈ 111km
                lat_delta = radius / 111.0
                lng_delta = radius / (111.0 * abs(lat))
                
                queryset = queryset.filter(
                    vendor__latitude__range=(lat - lat_delta, lat + lat_delta),
                    vendor__longitude__range=(lng - lng_delta, lng + lng_delta)
                )
            except (ValueError, TypeError):
                pass
        
        return queryset

    @action(detail=False, methods=['get'])
    def nearby(self, request):
        """Get services near a specific location"""
        lat = request.query_params.get('lat')
        lng = request.query_params.get('lng')
        
        if not lat or not lng:
            return Response(
                {'error': 'Latitude and longitude parameters are required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        services = self.get_queryset()
        serializer = self.get_serializer(services, many=True)
        return Response(serializer.data)

    def perform_create(self, serializer):
        # Only vendors can create services
        if hasattr(self.request.user, 'vendor_profile'):
            serializer.save(vendor=self.request.user.vendor_profile)
        else:
            raise PermissionError("Only vendors can create services")
        
    def mapbox_config(request):
        """
        API endpoint to provide Mapbox configuration to frontend
        """
        return JsonResponse({
            'accessToken': settings.MAPBOX_ACCESS_TOKEN,
            'styleUrl': settings.MAPBOX_STYLE_URL,
        })