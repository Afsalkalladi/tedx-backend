# 🔐 TEDx Authentication API

A secure, production-ready authentication system built with Django REST Framework. Features include JWT session management, Google OAuth2 login, and strict role-based access control. Designed for quick development, reliable deployment, and robust security.

---

## 🚀 Features

- JWT Authentication (Access + Refresh Tokens)
- Google OAuth2 Integration
- Role-Based Access Control (User, Staff, Superuser)
- Secure Password Hashing (PBKDF2)
- Environment-Specific Superuser Creation
- Full CORS Support for Frontend Integration
- Built-in Health Check Endpoint
- SQLite (Dev) & PostgreSQL (Prod) support
- 23-Test Suite with 100% Requirement Coverage

---

## 🌐 Live API

**Base URL:** `https://tedx-backend-6qlj.onrender.com`  
**Test Credentials:**

- **Email:** `tedx@test.com`
- **Password:** `tedx@123`

### 🔍 Try It Out

**Health Check**

```bash
curl https://tedx-backend-6qlj.onrender.com/health/
```

**Login**

```bash
curl -X POST https://tedx-backend-6qlj.onrender.com/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "tedx@test.com", "password": "tedx@123"}'
```

**Access Profile**

```bash
curl -X GET https://tedx-backend-6qlj.onrender.com/api/auth/profile/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 📡 API Endpoints

| Method | Endpoint                 | Description            | Auth      |
| ------ | ------------------------ | ---------------------- | --------- |
| GET    | `/health/`               | Health check           | ❌        |
| POST   | `/api/auth/register/`    | Register new user      | ❌        |
| POST   | `/api/auth/login/`       | Login (email/password) | ❌        |
| POST   | `/api/auth/google-auth/` | Login with Google      | ❌        |
| POST   | `/api/auth/refresh/`     | Refresh JWT token      | ❌        |
| GET    | `/api/auth/profile/`     | Authenticated profile  | ✅        |
| GET    | `/api/auth/staff-only/`  | Staff-only access      | Staff+    |
| GET    | `/api/auth/admin-only/`  | Admin-only access      | Superuser |
| GET    | `/api/auth/users/`       | List users             | Staff+    |

---

## 🛠️ Setup Instructions

### 🔧 Prerequisites

- Python 3.8+
- Git

### ⚙️ Quickstart (Dev Environment)

```bash
git clone https://github.com/Afsalkalladi/tedx-backend.git
cd tedx-backend

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env  # Edit as needed
python manage.py migrate
python manage.py runserver
```

Your API will be available at: `http://localhost:8000`

---

## 📂 Environment Configuration (`.env`)

> Create a `.env` file in the project root using the template below:

```env
# Django Core
SECRET_KEY=your-secret-key-here
DEBUG=True  # Set to False in production

# Database
DATABASE_URL=sqlite:///db.sqlite3  # For dev
# DATABASE_URL=postgresql://<username>:<password>@<host>/<db>  # For prod

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Hosts
ALLOWED_HOSTS=localhost,127.0.0.1,tedx-backend.example.com

# Superuser creation (used only during production setup)
SUPERUSER_CREATION_KEY=TEDx_SuperUser_Production_Key_2025
```

---

## 🧪 Testing & QA

Run test suites to verify setup and functionality:

```bash
# Django test runner
python manage.py test authentication.test
```

### ✅ Coverage Summary

- Registration / Login
- Secure Password Hashing
- JWT Token Flow (access + refresh)
- Google OAuth
- Role-Based Access
- Token Expiry + Validation
- Superuser Creation Protection

```
✅ 23/23 Tests Passed
🎯 100% Requirement Coverage
```

---

## 📁 Project Structure

```
tedx-backend/
├── auth_api/               # Project settings and URLs
├── authentication/         # Core app: models, views, tests, etc.
├── requirements.txt        # Dependencies
├── .env            # Env config
```

---

## 📬 Postman Collection (Optional)

Use `TEDx_Auth_Complete_Testing.postman_collection.json` to test:

- All endpoints
- Auth flow (login, refresh)
- Role promotions/demotions
- Cleanup logic

Set environment variables in Postman:

```env
base_url=https://tedx-backend-6qlj.onrender.com
admin_email=tedx@test.com
admin_password=tedx@123
```

---

## ✅ Ready for Production

- PostgreSQL config included
- Environment-specific security
- Superuser lock for production
- CORS & Host whitelisting
- Render-compatible

---

**Live Demo**: [https://tedx-backend-6qlj.onrender.com]
**Health Check**: [https://tedx-backend-6qlj.onrender.com/health/]

```

```
