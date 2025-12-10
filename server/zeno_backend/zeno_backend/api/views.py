# api/views.py
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.reverse import reverse

@api_view(['GET'])
def api_root(request, format=None):
    return Response({
        'users': {
            'login': reverse('auth-login', request=request, format=format),
            'register': reverse('auth-register', request=request, format=format),
            'profile': reverse('user-me', request=request, format=format),
            'users_list': reverse('user-list', request=request, format=format),
        },
        'services': reverse('service-list', request=request, format=format),
        'vendors': reverse('vendor-list', request=request, format=format),
        'orders': reverse('order-list', request=request, format=format),
        'payments': reverse('payment-list', request=request, format=format),
        'documentation': reverse('api-docs', request=request, format=format),
        'health': reverse('health-check', request=request, format=format),
        'version': reverse('version-info', request=request, format=format),
    })