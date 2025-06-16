from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
import json

User = get_user_model()

class AuthenticationTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'first_name': 'Test',
            'last_name': 'User',
            'password': 'SecurePass123!',
            'password_confirm': 'SecurePass123!'
        }
        
    def test_user_registration(self):
        """Test user registration with valid data"""
        response = self.client.post('/api/auth/register/', self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('user', response.data)
        self.assertIn('tokens', response.data)
        
    def test_user_registration_invalid_email(self):
        """Test registration with invalid email"""
        self.user_data['email'] = 'invalid-email'
        response = self.client.post('/api/auth/register/', self.user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_user_registration_password_mismatch(self):
        """Test registration with password mismatch"""
        self.user_data['password_confirm'] = 'DifferentPassword'
        response = self.client.post('/api/auth/register/', self.user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_user_login(self):
        """Test user login with valid credentials"""
        # First register a user
        User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='SecurePass123!'
        )
        
        login_data = {
            'email': 'test@example.com',
            'password': 'SecurePass123!'
        }
        response = self.client.post('/api/auth/login/', login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('tokens', response.data)
        
    def test_user_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        login_data = {
            'email': 'wrong@example.com',
            'password': 'wrongpassword'
        }
        response = self.client.post('/api/auth/login/', login_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_profile_access_authenticated(self):
        """Test profile access with authentication"""
        user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='SecurePass123!'
        )
        self.client.force_authenticate(user=user)
        
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user', response.data)
        
    def test_profile_access_unauthenticated(self):
        """Test profile access without authentication"""
        response = self.client.get('/api/auth/profile/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def test_admin_dashboard_access_admin_user(self):
        """Test admin dashboard access with admin user"""
        admin_user = User.objects.create_user(
            email='admin@example.com',
            username='admin',
            password='AdminPass123!',
            role='admin'
        )
        self.client.force_authenticate(user=admin_user)
        
        response = self.client.get('/api/auth/admin/dashboard/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
    def test_admin_dashboard_access_regular_user(self):
        """Test admin dashboard access with regular user"""
        user = User.objects.create_user(
            email='user@example.com',
            username='user',
            password='UserPass123!',
            role='user'
        )
        self.client.force_authenticate(user=user)
        
        response = self.client.get('/api/auth/admin/dashboard/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)