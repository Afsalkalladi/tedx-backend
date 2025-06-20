from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from django.conf import settings
from .models import User
from .serializers import (
    UserRegistrationSerializer, 
    UserLoginSerializer, 
    GoogleAuthSerializer,
    UserSerializer,
    RoleChangeSerializer
)
from .permissions import IsSuperuser, IsStaffOrAbove

def get_tokens_for_user(user):
    """Generate JWT tokens for a user"""
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register(request):
    """Register a new user with email and password"""
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        tokens = get_tokens_for_user(user)
        return Response({
            'message': 'User created successfully',
            'user': UserSerializer(user).data,
            'tokens': tokens
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login(request):
    """Login with email and password"""
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        tokens = get_tokens_for_user(user)
        return Response({
            'message': 'Login successful',
            'user': UserSerializer(user).data,
            'tokens': tokens
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def google_auth(request):
    """Authenticate with Google OAuth"""
    serializer = GoogleAuthSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    google_token = serializer.validated_data['google_token']
    try:
        idinfo = id_token.verify_oauth2_token(
            google_token, 
            google_requests.Request(), 
            settings.GOOGLE_CLIENT_ID
        )
        email = idinfo['email']
        google_id_val = idinfo['sub']
        name = idinfo.get('name', '')
        name_parts = name.split(' ') if name else ['']
        first_name = name_parts[0]
        last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': email,
                'google_id': google_id_val,
                'is_google_user': True,
                'first_name': first_name,
                'last_name': last_name,
                # Security: Ensure Google auth cannot create privileged users
                'is_superuser': False,
                'is_staff': False
            }
        )
        
        # Always update profile on login for Google users
        if not created:
            user.google_id = google_id_val
            user.is_google_user = True
            user.first_name = first_name
            user.last_name = last_name
            user.save()

        tokens = get_tokens_for_user(user)
        return Response({
            'message': 'Google authentication successful',
            'user': UserSerializer(user).data,
            'tokens': tokens
        }, status=status.HTTP_200_OK)
    except ValueError as e:
        return Response({'error': f'Invalid Google token: {str(e)}'}, 
                       status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def profile(request):
    """Get user profile information"""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def refresh_token(request):
    """Refresh an expired access token"""
    refresh_token_val = request.data.get('refresh')
    if not refresh_token_val:
        return Response({'error': 'Refresh token required'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        refresh = RefreshToken(refresh_token_val)
        access_token = str(refresh.access_token)
        return Response({'access': access_token})
    except (ValueError, TokenError) as e:
        return Response({'error': f'Invalid refresh token: {str(e)}'}, 
                        status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
@permission_classes([IsStaffOrAbove])
def user_list(request):
    """Get all user accounts (staff and superuser only)"""
    users = User.objects.all().order_by('-created_at')
    serializer = UserSerializer(users, many=True)
    return Response({
        'count': users.count(),
        'users': serializer.data
    }, status=status.HTTP_200_OK)

@api_view(['PATCH'])
@permission_classes([IsSuperuser])
def change_user_role(request, user_id):
    """Change user role - superuser only"""
    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    # Prevent users from changing their own role
    if target_user == request.user:
        return Response({'error': 'You cannot change your own role'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Prevent changing superuser roles
    if target_user.is_superuser:
        return Response({
            'error': 'Cannot modify superuser roles'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    serializer = RoleChangeSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    role = serializer.validated_data['role']
    
    if role == 'staff':
        target_user.is_staff = True
        message = f'User {target_user.email} promoted to staff'
    else:  # role == 'user'
        target_user.is_staff = False
        message = f'User {target_user.email} changed to regular user'
    
    target_user.save()
    
    return Response({
        'message': message,
        'user': UserSerializer(target_user).data
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsStaffOrAbove])
def staff_only(request):
    """Endpoint accessible to staff and superusers"""
    return Response({
        'message': 'Staff access granted',
        'user_type': request.user.user_type,
        'data': 'This data is accessible to staff and above'
    })

@api_view(['GET'])
@permission_classes([IsSuperuser])
def admin_only(request):
    """Endpoint accessible only to superusers"""
    return Response({
        'message': 'Admin access granted',
        'data': 'This is superuser-only data'
    })