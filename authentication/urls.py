from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('google-login/', views.google_login, name='google_login'),
    path('profile/', views.profile, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('token/refresh/', views.refresh_token, name='token_refresh'),
]