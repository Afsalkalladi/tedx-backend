from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # Authentication
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('google-auth/', views.google_auth, name='google_auth'),
    path('refresh-token/', views.refresh_token, name='refresh_token'),
    
    # User profile
    path('profile/', views.profile, name='profile'),
    
    # User management (superuser only)
    path('users/', views.user_list, name='user_list'),
    path('users/<int:user_id>/change-role/', views.change_user_role, name='change_user_role'),
    
    # Access level testing
    path('staff-only/', views.staff_only, name='staff_only'),
    path('admin-only/', views.admin_only, name='admin_only'),
]
