from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

@require_http_methods(["GET"])
def health_check(request):
    """Health check endpoint for deployment monitoring"""
    return JsonResponse({
        'status': 'healthy',
        'service': 'tedx-auth-api',
        'version': '1.0.0'
    })

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls', namespace='authentication')),
    path('health/', health_check, name='health_check'),
]
