# zeno_backend/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # API v1
    path('api/v1/users/', include('users.urls')),
    path('api/v1/services/', include('services.urls')),
    path('api/v1/vendors/', include('vendors.urls')),
    path('api/v1/orders/', include('orders.urls')),
    path('api/v1/payments/', include('payments.urls')),
    
    # API root redirect
    path('api/', RedirectView.as_view(url='/api/v1/', permanent=False)),
    path('api/v1/', RedirectView.as_view(pattern_name='api-root'), name='api-root'),
    
    # Health check (global)
    path('health/', include('users.urls')),
    
    # Documentation
    path('api/docs/', include('docs.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Debug toolbar
    # import debug_toolbar
    # urlpatterns += [path('__debug__/', include(debug_toolbar.urls))]