from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('google-auth/', views.google_auth, name='google_auth'),
    path('profile/', views.profile, name='profile'),
    path('admin-only/', views.admin_only, name='admin_only'),
    path('users/', views.user_list, name='user_list'),
    path('refresh-token/', views.refresh_token, name='refresh_token'),
    path('create-first-admin/', views.create_first_admin, name='create_first_admin'),
]
