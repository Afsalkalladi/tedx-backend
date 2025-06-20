# 🔐 Django JWT Authentication API

A secure, extensible authentication API built using **Django REST Framework**, **JWT (SimpleJWT)**, and **Google OAuth**.

## 🚀 Features

- ✅ Email/password registration and login
- ✅ Google OAuth 2.0 login
- ✅ JWT access & refresh token support
- ✅ Authenticated user profile
- ✅ Admin-only protected routes
- ✅ Paginated user list with role filter
- ✅ One-time admin bootstrap endpoint

---

## 📅 Installation (from GitHub)

```bash
# 1. Clone the repository
git clone https://github.com/Afsalkalladi/tedx-backend.git
cd tedx-backend

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create a .env file (see below)

# 5. Apply migrations
python manage.py migrate

# 6. Run the development server
python manage.py runserver
```

---

## ⚙️ Environment Variables (`.env`)

```env
# === Django Core ===
SECRET_KEY=your-super-secret-key
DEBUG=False

# === Database Configuration ===
# For SQLite:
# DATABASE_URL=sqlite:///db.sqlite3
# For PostgreSQL:
DATABASE_URL=postgresql://<user>:<password>@<host>/<database>

# === Google OAuth ===
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# === CORS ===
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# === Security ===
ALLOWED_HOSTS=localhost,127.0.0.1,tedx-backend.example.com

# === Optional ===
ENVIRONMENT=development
```

> ⚠️ \*\*Do not commit \*\***`.env`** — it must be added to `.gitignore`.

---

## 📂 API Endpoints

### 🟢 `POST /api/auth/register/`

➡️ Register a new user using email and password.

### 🟢 `POST /api/auth/login/`

➡️ Log in and receive access + refresh tokens.

### 🟢 `POST /api/auth/google-auth/`

➡️ Authenticate or register using a Google OAuth2 token.

### 🔵 `GET /api/auth/profile/`

🔒 Requires JWT access token.
➡️ Get authenticated user's profile data.

### 🔵 `GET /api/auth/admin-only/`

🔒 Requires admin role.
➡️ Access admin-only protected data.

### 🔵 `GET /api/auth/users/`

🔒 Requires admin role.
➡️ Get a paginated list of all users, with optional role filtering.

### 🟢 `POST /api/auth/refresh-token/`

➡️ Exchange a valid refresh token for a new access token.

### 🟢 `POST /api/auth/create-first-admin/`

⚠️ One-time use only.
➡️ Create the first admin user if none exist.

---

## 🔑 Authentication

All protected routes require a JWT access token:

```
Authorization: Bearer <access_token>
```

To get a new access token when it expires, use the `/refresh-token/` endpoint with the refresh token.

---

## 👑 First Admin Bootstrap

Use the `/create-first-admin/` endpoint to create the very first admin account.
This is **only allowed once**. After that, it returns a `403 Forbidden` if an admin already exists.

---
