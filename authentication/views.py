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
    UserSerializer
)
from .permissions import IsAdminUser

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
                'last_name': last_name
            }
        )
        
        # Always update profile on login for Google users
        if not created:
            user.google_id = google_id_val
            user.is_google_user = True
            # Update name on login
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

@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_only(request):
    """Endpoint accessible only to admin users"""
    return Response({
        'message': 'Admin access granted',
        'admin_data': 'This is sensitive admin data'
    })

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
@permission_classes([IsAdminUser])
def user_list(request):
    """Get all user accounts (admin only) with optional filtering by role"""
    # Get query parameters
    role = request.query_params.get('role', None)
    page = int(request.query_params.get('page', 1))
    page_size = int(request.query_params.get('page_size', 10))
    
    # Filter users
    users = User.objects.all().order_by('-created_at')
    if role:
        if role.lower() in [User.ADMIN.lower(), User.USER.lower()]:
            users = users.filter(role=role.lower())
        else:
            return Response({
                'error': f"Invalid role filter. Valid values are '{User.ADMIN}' or '{User.USER}'."
            }, status=status.HTTP_400_BAD_REQUEST)
    
    # Calculate pagination values
    total = users.count()
    start = (page - 1) * page_size
    end = start + page_size
    users = users[start:end]
    
    # Serialize users
    serializer = UserSerializer(users, many=True)
    
    return Response({
        'count': total,
        'pages': (total + page_size - 1) // page_size,
        'current_page': page,
        'page_size': page_size,
        'users': serializer.data
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def create_first_admin(request):
    """Create the first admin user (only works if no admins exist)"""
    if User.objects.filter(role=User.ADMIN).exists():
        return Response({'error': 'Admin already exists'}, status=status.HTTP_403_FORBIDDEN)
        
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        user.role = User.ADMIN
        user.is_staff = True
        user.is_superuser = True
        user.save()
        
        tokens = get_tokens_for_user(user)
        return Response({
            'message': 'Admin created successfully',
            'user': UserSerializer(user).data,
            'tokens': tokens
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)