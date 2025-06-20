# Technical Overview: Django Authentication API

## 🏗️ Architecture Overview

This Django-based authentication API implements a secure, role-based authentication system with multiple authentication methods, JWT token management, and production-ready security features.

### Core Components

```
├── auth_api/                   # Django Project Root
│   ├── settings.py            # Configuration & Security Settings
│   ├── urls.py                # Main URL routing
│   ├── wsgi.py/asgi.py        # Production server interfaces
├── authentication/            # Main Authentication App
│   ├── models.py              # User model & database schema
│   ├── views.py               # API endpoints & business logic
│   ├── serializers.py         # Data validation & serialization
│   ├── permissions.py         # Role-based access control
│   ├── urls.py                # Authentication-specific routes
│   └── test.py                # Comprehensive test suite
```

## 🔐 Authentication Flow

### 1. Email/Password Authentication

**Registration Process:**

```python
POST /auth/register/
{
    "username": "john_doe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "password_confirm": "SecurePass123!"
}
```

**Flow:**

1. `UserRegistrationSerializer` validates input data
2. Password validation using Django's built-in validators
3. Email uniqueness check
4. Password hashing with PBKDF2 (Django default)
5. User creation with `is_superuser=False`, `is_staff=False`
6. JWT token generation via `get_tokens_for_user()`
7. Response with user data and tokens

**Login Process:**

```python
POST /auth/login/
{
    "email": "john@example.com",
    "password": "SecurePass123!"
}
```

**Flow:**

1. `UserLoginSerializer` validates credentials
2. Django's `authenticate()` function verifies password hash
3. Account status check (`is_active`)
4. JWT token generation
5. Response with user data and tokens

### 2. Google OAuth Authentication

**OAuth Flow:**

```python
POST /auth/google/
{
    "google_token": "google_id_token_here"
}
```

**Technical Process:**

1. `GoogleAuthSerializer` validates token format
2. Google ID token verification using `google.oauth2.id_token`
3. Extract user profile data (email, name, google_id)
4. User lookup/creation with `get_or_create()`
5. Security enforcement: `is_superuser=False`, `is_staff=False`
6. Profile synchronization on each login
7. JWT token generation

## 🎫 JWT Token System

### Token Architecture

- **Access Token**: Short-lived (15 minutes), used for API authentication
- **Refresh Token**: Long-lived (1 day), used to generate new access tokens

### Token Generation

```python
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
```

### Token Refresh Endpoint

```python
POST /auth/refresh/
{
    "refresh": "refresh_token_here"
}
```

**Security Features:**

- Automatic token expiration
- Secure token validation
- Error handling for invalid/expired tokens
- No token blacklisting (can be added if needed)

## 👥 Role-Based Access Control (RBAC)

### User Hierarchy

1. **Regular User** (`user`): Basic access, can view own profile
2. **Staff** (`staff`): Enhanced access, can view user lists
3. **Superuser** (`superuser`): Full administrative access

### Custom Permissions

```python
class IsSuperuser(permissions.BasePermission):
    """Superuser-only operations"""
    def has_permission(self, request, view):
        return (request.user and request.user.is_authenticated
                and request.user.is_superuser)

class IsStaffOrAbove(permissions.BasePermission):
    """Staff and superuser operations"""
    def has_permission(self, request, view):
        return (request.user and request.user.is_authenticated and
                (request.user.is_staff or request.user.is_superuser))
```

### Role Management

- Only superusers can change user roles
- Users cannot change their own roles
- Superuser roles cannot be modified (protection)
- Role changes are logged and traceable

## 🗄️ Database Schema

### User Model (Extended AbstractUser)

```python
class User(AbstractUser):
    email = models.EmailField(unique=True)           # Primary identifier
    is_google_user = models.BooleanField(default=False)  # OAuth flag
    google_id = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'  # Login with email instead of username
    REQUIRED_FIELDS = ['username']
```

**Key Features:**

- Email-based authentication
- Google OAuth integration support
- Timestamp tracking
- Inheritance from Django's AbstractUser (includes permissions, groups, etc.)

## 🛡️ Security Implementation

### 1. Password Security

- **Hashing**: PBKDF2 with SHA256 (Django default)
- **Validation**: Django's built-in password validators
- **Minimum Requirements**: Length, complexity, common password checks

### 2. Superuser Creation Protection

```python
# In settings.py
if 'createsuperuser' in sys.argv:
    if not DEBUG:
        protection_key = os.getenv('SUPERUSER_CREATION_KEY')
        expected_key = 'TEDx_SuperUser_Production_Key_2025'

        if protection_key != expected_key:
            print("🚨 SECURITY ALERT: Superuser creation blocked!")
            sys.exit(1)
```

### 3. OAuth Security

- Google ID token verification
- Profile data validation
- Automatic privilege restriction for OAuth users
- Protection against privilege escalation

### 4. API Security

- JWT token authentication
- Role-based endpoint protection
- Input validation and sanitization
- CORS configuration
- Rate limiting ready (can be added)

## 🌐 API Endpoints

### Public Endpoints (No Authentication)

```
POST /auth/register/         # User registration
POST /auth/login/            # Email/password login
POST /auth/google/           # Google OAuth login
POST /auth/refresh/          # Token refresh
```

### Protected Endpoints (Authentication Required)

```
GET  /auth/profile/          # User profile (any authenticated user)
GET  /auth/users/            # User list (staff+)
PATCH /auth/users/{id}/role/ # Role management (superuser only)
GET  /auth/staff-only/       # Staff test endpoint
GET  /auth/admin-only/       # Superuser test endpoint
```

## 🔧 Configuration Management

### Environment Variables

```bash
# Core Django
SECRET_KEY=your-secret-key
DEBUG=False
ALLOWED_HOSTS=localhost,yourdomain.com

# Database
DATABASE_URL=postgresql://user:pass@host:port/db

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id

# Security
SUPERUSER_CREATION_KEY=TEDx_SuperUser_Production_Key_2025
```

### Production Settings

- **Database**: PostgreSQL with connection pooling
- **Static Files**: WhiteNoise for efficient serving
- **CORS**: Configured for cross-origin requests
- **Security Headers**: CSP, HSTS, etc. (can be enhanced)

## 🧪 Testing Strategy

### Test Coverage

The `authentication/test.py` file includes:

1. **Unit Tests**: Individual component testing
2. **Integration Tests**: End-to-end API testing
3. **Security Tests**: Permission and authorization validation
4. **Edge Cases**: Error handling and boundary conditions

### Test Categories

```python
class AuthenticationTestCase(TestCase):
    # Registration tests (valid/invalid data)
    # Login tests (success/failure scenarios)
    # Google OAuth tests (token validation)
    # Permission tests (role-based access)
    # Token management tests (refresh/expiry)
    # Security tests (privilege escalation prevention)
```

## 🚀 Production Deployment

### Render.com Configuration

```yaml
# render.yaml
services:
  - type: web
    name: tedx-auth-api
    env: python
    buildCommand: "pip install -r requirements.txt && python manage.py collectstatic --noinput && python manage.py migrate"
    startCommand: "gunicorn auth_api.wsgi:application"
```

### Production Checklist

- ✅ Environment variables configured
- ✅ Database migrations applied
- ✅ Static files collected
- ✅ Debug mode disabled
- ✅ Security keys in place
- ✅ HTTPS enforced
- ✅ Error logging configured

## 🔄 Development Workflow

### Local Development

```bash
# Setup
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Database
python manage.py migrate
python manage.py createsuperuser

# Run
python manage.py runserver
```

### Testing

```bash
# Run all tests
python manage.py test authentication

# Run with coverage
coverage run --source='.' manage.py test authentication
coverage report
```

## 📊 Performance Considerations

### Database Optimization

- Indexed email field for fast lookups
- Efficient user queries with select_related/prefetch_related
- Connection pooling in production

### Security Performance

- JWT token validation is stateless
- Minimal database queries for authentication
- Efficient permission checking

### Scalability Features

- Stateless authentication (JWT)
- Database-agnostic design
- Horizontal scaling ready
- Caching layer ready (Redis can be added)

## 🔮 Extension Points

### Ready for Enhancement

1. **Rate Limiting**: Add Django-ratelimit or similar
2. **Email Verification**: Extend registration flow
3. **Password Reset**: Email-based password recovery
4. **Multi-Factor Authentication**: TOTP/SMS integration
5. **Social Auth**: Additional OAuth providers
6. **Audit Logging**: Track authentication events
7. **Session Management**: Token blacklisting/revocation

### Code Structure for Extensions

The modular design makes it easy to:

- Add new authentication methods
- Extend user models
- Implement additional permissions
- Add middleware for logging/monitoring
- Integrate with external services

---

This authentication API provides a solid foundation for secure user management with room for growth and enterprise-level features.
