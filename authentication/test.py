from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from .models import User
from unittest.mock import patch
from django.contrib.auth.hashers import check_password
from datetime import timedelta

class AuthenticationTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        # Add namespace 'authentication:' to all URL names
        self.register_url = reverse('authentication:register')
        self.login_url = reverse('authentication:login')
        self.google_auth_url = reverse('authentication:google_auth')
        self.profile_url = reverse('authentication:profile')
        self.admin_only_url = reverse('authentication:admin_only')
        self.refresh_token_url = reverse('authentication:refresh_token')
        
        # Test user data
        self.user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "SecureP@ss123",
            "password_confirm": "SecureP@ss123"
        }
        
        # Create admin user directly
        self.admin_user = User.objects.create_user(
            email="admin@example.com",
            username="adminuser",
            password="AdminPass123",
            role=User.ADMIN
        )

    # 1. Email & Password Signup Tests
    def test_user_registration_valid(self):
        """Test user can register with valid credentials"""
        response = self.client.post(self.register_url, self.user_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('tokens', response.data)
        self.assertIn('user', response.data)
        self.assertTrue(User.objects.filter(email=self.user_data['email']).exists())
    
    def test_user_registration_invalid_email(self):
        """Test registration with invalid email format is rejected"""
        invalid_data = self.user_data.copy()
        invalid_data['email'] = "invalid-email"
        response = self.client.post(self.register_url, invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_user_registration_password_mismatch(self):
        """Test registration with mismatched passwords is rejected"""
        invalid_data = self.user_data.copy()
        invalid_data['password_confirm'] = "DifferentP@ss123"
        response = self.client.post(self.register_url, invalid_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_user_registration_email_already_exists(self):
        """Test registration with existing email is rejected"""
        # First create a user
        self.client.post(self.register_url, self.user_data, format='json')
        
        # Try to register again with same email
        duplicate_data = self.user_data.copy()
        duplicate_data['username'] = "anotheruser"
        response = self.client.post(self.register_url, duplicate_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # 2. Password Security Tests
    def test_password_hashing(self):
        """Test password is properly hashed in database"""
        self.client.post(self.register_url, self.user_data, format='json')
        user = User.objects.get(email=self.user_data['email'])
        self.assertNotEqual(user.password, self.user_data['password'])
        self.assertTrue(user.password.startswith('pbkdf2_'))
    
    def test_weak_password_rejected(self):
        """Test weak passwords are rejected during registration"""
        weak_data = self.user_data.copy()
        weak_data['password'] = "password"
        weak_data['password_confirm'] = "password"
        response = self.client.post(self.register_url, weak_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # 3. Login Tests
    def test_user_login_valid(self):
        """Test user can login with valid credentials"""
        # First create a user
        self.client.post(self.register_url, self.user_data, format='json')
        
        # Now try to login
        login_data = {
            "email": self.user_data['email'],
            "password": self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('tokens', response.data)
    
    def test_user_login_invalid_credentials(self):
        """Test login with invalid credentials is rejected"""
        # First create a user
        self.client.post(self.register_url, self.user_data, format='json')
        
        # Try to login with wrong password
        login_data = {
            "email": self.user_data['email'],
            "password": "WrongPassword123"
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_inactive_user_login(self):
        """Test inactive user cannot login"""
        # First create a user
        self.client.post(self.register_url, self.user_data, format='json')
        
        # Make user inactive
        user = User.objects.get(email=self.user_data['email'])
        user.is_active = False
        user.save()
        
        # Try to login
        login_data = {
            "email": self.user_data['email'],
            "password": self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # 4. JWT Token Tests
    def test_access_protected_endpoint_with_token(self):
        """Test protected endpoint is accessible with valid token"""
        # First create a user and login
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {"email": self.user_data['email'], "password": self.user_data['password']}
        login_response = self.client.post(self.login_url, login_data, format='json')
        
        # Access protected endpoint with token
        access_token = login_response.data['tokens']['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_access_protected_endpoint_without_token(self):
        """Test protected endpoint is inaccessible without token"""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    @patch('rest_framework_simplejwt.tokens.AccessToken.lifetime', new=timedelta(seconds=1))  # 1 second
    def test_access_protected_endpoint_with_expired_token(self):
        """Test expired token is rejected"""
        import time
        
        # First create a user and login
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {"email": self.user_data['email'], "password": self.user_data['password']}
        login_response = self.client.post(self.login_url, login_data, format='json')
        
        # Wait for token to expire
        time.sleep(2)
        
        # Try to access protected endpoint with expired token
        access_token = login_response.data['tokens']['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # 5. Google OAuth Tests
    @patch('google.oauth2.id_token.verify_oauth2_token')
    def test_google_auth_success(self, mock_verify_token):
        """Test Google authentication with valid token"""
        # Mock response from Google
        mock_verify_token.return_value = {
            'sub': '123456789',
            'email': 'google@example.com',
            'name': 'Google User'
        }
        
        # Attempt Google authentication
        google_data = {"google_token": "valid_mock_token"}
        response = self.client.post(self.google_auth_url, google_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('tokens', response.data)
        self.assertTrue(User.objects.filter(email='google@example.com').exists())
        self.assertTrue(User.objects.get(email='google@example.com').is_google_user)
    
    @patch('google.oauth2.id_token.verify_oauth2_token')
    def test_google_auth_invalid_token(self, mock_verify_token):
        """Test Google authentication with invalid token"""
        mock_verify_token.side_effect = ValueError("Invalid token")
        
        google_data = {"google_token": "invalid_token"}
        response = self.client.post(self.google_auth_url, google_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    @patch('google.oauth2.id_token.verify_oauth2_token')
    def test_google_user_profile_update(self, mock_verify_token):
        """Test Google user profile is updated on subsequent logins"""
        # First login with one name
        mock_verify_token.return_value = {
            'sub': '123456789',
            'email': 'google@example.com',
            'name': 'Original Name'
        }
        google_data = {"google_token": "valid_mock_token"}
        self.client.post(self.google_auth_url, google_data, format='json')
        
        # Update mock and login again with different name
        mock_verify_token.return_value = {
            'sub': '123456789',
            'email': 'google@example.com',
            'name': 'Updated Name'
        }
        self.client.post(self.google_auth_url, google_data, format='json')
        
        # Check if name was updated
        user = User.objects.get(email='google@example.com')
        self.assertEqual(user.first_name, 'Updated')

    # 6. Role-Based Access Tests
    def test_admin_access_to_admin_endpoint(self):
        """Test admin can access admin-only endpoint"""
        # Login as admin
        login_data = {"email": "admin@example.com", "password": "AdminPass123"}
        login_response = self.client.post(self.login_url, login_data, format='json')
        
        # Access admin endpoint
        access_token = login_response.data['tokens']['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(self.admin_only_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_regular_user_access_to_admin_endpoint(self):
        """Test regular user cannot access admin-only endpoint"""
        # Register and login as regular user
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {"email": self.user_data['email'], "password": self.user_data['password']}
        login_response = self.client.post(self.login_url, login_data, format='json')
        
        # Try to access admin endpoint
        access_token = login_response.data['tokens']['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(self.admin_only_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
    
    def test_role_checking_property(self):
        """Test is_admin property works correctly"""
        # Create regular user
        self.client.post(self.register_url, self.user_data, format='json')
        user = User.objects.get(email=self.user_data['email'])
        
        # Check roles
        self.assertTrue(self.admin_user.is_admin)
        self.assertFalse(user.is_admin)

    # 7. Token Refresh Tests
    def test_token_refresh_valid(self):
        """Test token refresh with valid refresh token"""
        # First login to get tokens
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {"email": self.user_data['email'], "password": self.user_data['password']}
        login_response = self.client.post(self.login_url, login_data, format='json')
        
        # Try to refresh token
        refresh_data = {"refresh": login_response.data['tokens']['refresh']}
        response = self.client.post(self.refresh_token_url, refresh_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
    
    def test_token_refresh_invalid(self):
        """Test token refresh with invalid refresh token"""
        refresh_data = {"refresh": "invalid_refresh_token"}
        response = self.client.post(self.refresh_token_url, refresh_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    @patch('rest_framework_simplejwt.tokens.RefreshToken.lifetime', new=timedelta(seconds=1))  # 1 second
    def test_token_refresh_expired(self):
        """Test token refresh with expired refresh token"""
        import time
        
        # First login to get tokens
        self.client.post(self.register_url, self.user_data, format='json')
        login_data = {"email": self.user_data['email'], "password": self.user_data['password']}
        login_response = self.client.post(self.login_url, login_data, format='json')
        
        # Wait for token to expire
        time.sleep(2)
        
        # Try to refresh token
        refresh_data = {"refresh": login_response.data['tokens']['refresh']}
        response = self.client.post(self.refresh_token_url, refresh_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)