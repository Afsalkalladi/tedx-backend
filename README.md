**🔐 TEDx Authentication API** - Complete authentication system ready for local development and testing.validation

- **JWT Token Management** with access + refresh token pattern
- **Google OAuth 2.0 Integration** for seamless social login
- **Role-Based Access Control** (User/Staff/Superuser permissions)
- **Secure Password Hashing** using industry-standard PBKDF2

### 🛡️ Security Features

- **Input Validation** and sanitization
- **CORS Configuration** for frontend integration
- **No Privilege Escalation** vulnerabilities
- **Environment-Based Protection** mechanisms

### 🚀 Local Development Ready

- **Quick Setup** with SQLite database
- **Environment Variables** configuration
- **Comprehensive Test Suite** (23 tests)
- **Health Check Endpoint** for monitoring

---

## 🌐 Test the Live Production API

**Base URL**: `https://tedx-backend.onrender.com`

### Try These Endpoints:

#### Health Check

```bash
curl https://tedx-backend.onrender.com/health/
```

#### Register a New User

```bash
curl -X POST https://tedx-backend.onrender.com/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "password_confirm": "SecurePassword123!"
  }'
```

#### Login

```bash
curl -X POST https://tedx-backend.onrender.com/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePassword123!"
  }'
```

#### Access Protected Profile (use token from login response)

```bash
curl -X GET https://tedx-backend.onrender.com/api/auth/profile/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

### Available API Endpoints

| Endpoint                 | Method | Description          | Auth Required |
| ------------------------ | ------ | -------------------- | ------------- |
| `/health/`               | GET    | Health check         | No            |
| `/api/auth/register/`    | POST   | User registration    | No            |
| `/api/auth/login/`       | POST   | Email/password login | No            |
| `/api/auth/google-auth/` | POST   | Google OAuth login   | No            |
| `/api/auth/refresh/`     | POST   | Refresh JWT token    | No            |
| `/api/auth/profile/`     | GET    | User profile         | Yes           |
| `/api/auth/staff-only/`  | GET    | Staff operations     | Staff+        |
| `/api/auth/admin-only/`  | GET    | Admin operations     | Superuser     |
| `/api/auth/users/`       | GET    | User management      | Staff+        |

## 🔧 Technology Stack

- **Django 5.2+** - Web framework
- **Django REST Framework** - API toolkit
- **SimpleJWT** - JWT implementation
- **Google Auth Library** - OAuth integration
- **SQLite** - Local development database
- **PBKDF2** - Password hashing

---

## 🚀 Local Development Setup

### Prerequisites

- Python 3.8+
- Git

### Quick Setup (5 minutes)

```bash
# 1. Clone the repository
git clone https://github.com/Afsalkalladi/tedx-backend.git
cd tedx-backend

# 2. Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables (optional)
cp .env.example .env
# Edit .env file with your configuration (see below)

# 5. Run database migrations
python manage.py migrate

# 6. Create a superuser (optional)
python manage.py createsuperuser

# 7. Start development server
python manage.py runserver
```

Your API will be available at: `http://localhost:8000`

### 🔧 Environment Configuration (.env file)

Create a `.env` file in the project root (optional for basic functionality):

```env
# Django Configuration
SECRET_KEY=your-secret-key-here-generate-a-long-random-string
DEBUG=True

# Google OAuth (Optional - for social login testing)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# CORS & Security (Optional)
ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

**Note**: The app works without a `.env` file using Django defaults and SQLite.

### 🧪 Test Your Local API

Once the server is running at `http://localhost:8000`:

```bash
# Health check
curl http://localhost:8000/health/

# Register a new user
curl -X POST http://localhost:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "password_confirm": "SecurePassword123!"
  }'

# Login
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePassword123!"
  }'
```

### 🔍 Local API Endpoints

- **GET** `http://localhost:8000/health/` - Health check
- **POST** `http://localhost:8000/api/auth/register/` - User registration
- **POST** `http://localhost:8000/api/auth/login/` - User login
- **POST** `http://localhost:8000/api/auth/google-auth/` - Google OAuth login
- **POST** `http://localhost:8000/api/auth/refresh/` - Refresh JWT token
- **GET** `http://localhost:8000/api/auth/profile/` - User profile (requires auth)
- **GET** `http://localhost:8000/admin/` - Django admin panel

### 🧪 Running Tests

```bash
# Quick verification - all requirements
python test_runner.py requirements

# Full test suite (23 tests)
python test_runner.py all

# Django test runner
python manage.py test authentication.test
```

---

## 🧪 Postman Collection for API Testing

### 📦 Complete API Test Collection

We provide a comprehensive **Postman collection** that tests ALL endpoints with proper role-based access control:

**📁 Collection File**: `TEDx_Auth_Complete_Testing.postman_collection.json`

### 🚀 Features

✅ **Complete Role-Based Testing**:

- Regular User → Staff → Regular (full lifecycle)
- Tests ALL permission levels properly
- Real superuser/admin authentication
- Proper cleanup with role demotion

✅ **18 Comprehensive Test Scenarios**:

- API health check
- Admin authentication
- User registration and login
- Role-based access control verification
- Token refresh and validation
- Input validation testing
- Complete cleanup and demotion

✅ **Real Cleanup Implementation**:

- Demotes promoted users back to regular status
- Clears all tokens and variables
- Ensures no test data remains elevated

### 📋 How to Use

1. **Import the Collection**:

   - Open Postman
   - Import `TEDx_Auth_Complete_Testing.postman_collection.json`

2. **Set Environment Variables** (required for full testing):

   ```
   admin_email: your-admin@email.com
   admin_password: your-admin-password
   base_url: http://localhost:8000 (for local) or https://tedx-backend.onrender.com (for production)
   ```

3. **Run the Collection**:
   - Click "Run Collection" in Postman
   - All 18 tests will execute in sequence
   - Watch detailed logs in the console

### 💡 What It Tests

- **Authentication Flow**: Registration, login, token management
- **Role Restrictions**: User/staff/superuser access boundaries
- **Security**: Permission enforcement, privilege escalation prevention
- **Token Management**: Refresh, expiration, validation
- **Complete Lifecycle**: User creation → promotion → testing → demotion → cleanup

**🔄 True Cleanup**: The collection promotes a test user to staff, tests all permissions, then demotes them back to regular user and clears all session data.

---

## 🧪 Testing & Verification

### Requirement Compliance

✅ **Email & Password Authentication** - Complete registration/login flow  
✅ **Secure Password Hashing** - PBKDF2 with salt  
✅ **JWT Session Management** - Access + refresh token pattern  
✅ **Google OAuth Integration** - Social login with profile sync  
✅ **Role-Based Access Control** - User/Staff/Superuser levels  
✅ **Token Refresh Logic** - Automatic token renewal  
✅ **Production Security** - Superuser creation protection

### Test Coverage Report

```
Authentication Tests: 23/23 PASSED ✅
- User Registration: 4 tests
- Login/Logout: 3 tests
- JWT Token Management: 5 tests
- Google OAuth: 4 tests
- Role-Based Access: 4 tests
- Security Features: 3 tests

🎉 100% Requirement Coverage Achieved
```

---

## 🧪 Testing & Quality Assurance

### ✅ Comprehensive Test Suite

Our authentication system includes **23 comprehensive tests** covering all requirements:

#### 📊 Test Coverage

- **Email & Password Auth**: Registration, login, validation
- **Security**: Password hashing, token security, privilege escalation prevention
- **JWT Tokens**: Generation, validation, expiration, refresh
- **Google OAuth**: Token verification, user creation, profile updates
- **Role-Based Access**: User/staff/superuser permissions, endpoint protection
- **Token Refresh**: Valid/invalid tokens, expiration handling
- **Production Security**: Superuser creation protection

#### 🚀 Running Tests

```bash
# Quick verification - all requirements
python test_runner.py requirements

# Full test suite (23 tests)
python test_runner.py all

# Individual test suites
python test_runner.py main      # Core functionality (20 tests)
python test_runner.py security  # Security features (2 tests)
python test_runner.py verbose   # Detailed test output

# Django test runner
python manage.py test authentication.test
```

#### 📋 Test Results

```
✅ ALL REQUIREMENTS VERIFIED:
✅ Email & password signup/login with validation
✅ Secure password hashing
✅ JWT for login sessions
✅ Google Sign-In (OAuth)
✅ Role-based access (admin/user/staff)
✅ Token refresh logic
✅ Superuser creation protection

🎉 TEDx Authentication System - All 7 requirements implemented!
🚀 Ready for deployment on Render!
```

---

## 🛡️ Security Features

### 🔒 Production Security

- **Secure password hashing** with PBKDF2
- **JWT token authentication** with access/refresh pattern
- **Role-based access control** (user/staff/superuser)
- **Input validation** and sanitization
- **No privilege escalation** in registration or OAuth
- **Environment-based protection** for superuser creation
- **CORS configuration** for cross-origin requests

### 🔐 Authentication Security

- **Email format validation**
- **Password strength requirements**
- **Token expiration handling**
- **Invalid token rejection**
- **Session management**
- **OAuth token verification**

### 🛡️ Authorization Security

- **Role-based endpoint protection**
- **Permission-based access control**
- **Superuser-only role management**
- **Staff-level user listing**
- **Protected profile access**

---

## 📁 Project Structure

```
tedx-backend/
├── auth_api/                 # Django project settings
│   ├── settings.py          # Configuration
│   ├── urls.py              # Main URL routing
│   └── wsgi.py              # WSGI configuration
├── authentication/          # Authentication app
│   ├── models.py            # User model with Google OAuth support
│   ├── views.py             # API endpoints and authentication logic
│   ├── serializers.py       # Data validation and serialization
│   ├── permissions.py       # Role-based permission classes
│   ├── urls.py              # Authentication URL patterns
│   └── test.py              # Comprehensive test suite (23 tests)
├── requirements.txt         # Python dependencies
├── manage.py                # Django management script
└── README.md                # This documentation
```

## 🌟 Project Information

**🌐 Live Demo**: [https://tedx-backend.onrender.com](https://tedx-backend.onrender.com)  
**� Health Check**: [https://tedx-backend.onrender.com/health/](https://tedx-backend.onrender.com/health/)  
**💻 Technology**: Django REST Framework + PostgreSQL  
**🔐 Security**: JWT + OAuth + Role-based Access  
**🧪 Testing**: 23 comprehensive tests  
**📊 Coverage**: 100% requirement compliance

---
