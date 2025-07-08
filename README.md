
# Authentication System API

A secure RESTful API for user authentication with email verification, password reset, MFA, and session management.

## Table of Contents
- [Features](#features)
- [API Endpoints](#api-endpoints)
- [Setup](#setup)
- [Environment Variables](#environment-variables)
- [Testing](#testing)
- [Database Schema](#database-schema)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Security](#security)

## Features
✅ Email verification  
✅ JWT authentication  
✅ Password reset flow  
✅ Multi-factor authentication (TOTP)  
✅ Session management  
✅ Rate limiting  
✅ Secure password hashing (bcrypt)  
✅ CORS protection  

## API Endpoints

### Authentication
| Method | Endpoint          | Description                     |
|--------|-------------------|---------------------------------|
| POST   | `/register`       | Register new user               |
| GET    | `/verify-email`   | Verify email address            |
| POST   | `/login`          | User login                      |
| POST   | `/refresh-token`  | Refresh access token            |

### Password Management
| Method | Endpoint                     | Description                     |
|--------|------------------------------|---------------------------------|
| POST   | `/password-reset/request`    | Request password reset          |
| POST   | `/password-reset/confirm`    | Confirm password reset          |

### MFA Endpoints
| Method | Endpoint          | Description                     |
|--------|-------------------|---------------------------------|
| POST   | `/mfa/setup`      | Initialize MFA setup            |
| POST   | `/mfa/verify`     | Verify MFA token                |
| POST   | `/mfa/finalize`   | Complete MFA login              |

### User & Sessions
| Method | Endpoint          | Description                     |
|--------|-------------------|---------------------------------|
| GET    | `/profile`        | Get user profile                |
| GET    | `/sessions`       | List active sessions            |
| DELETE | `/sessions/:id`   | Revoke specific session         |

## Setup
1. Clone the repository
   ```bash
   git clone https://github.com/Oreva12/authentication-system.git
   ```
2. Install dependencies
   ```bash
   npm install
   ```
3. Set up PostgreSQL database
4. Configure environment variables (see below)
5. Start the server
   ```bash
   node server.js
   ```

## Environment Variables
Create a `.env` file in root directory:

```ini
# Database
DB_HOST=localhost
DB_USER=postgres
DB_PASSWORD=yourpassword
DB_NAME=auth_system
DB_PORT=5432
DB_SSL=false

# JWT
JWT_SECRET=your_jwt_secret
JWT_REFRESH_SECRET=your_refresh_secret

# App
PORT=3000
CORS_ORIGIN=*
```

## Testing
Run tests with Postman:

1. Import [Postman Collection](#) (link to your JSON)
2. Set environment variables in Postman
3. Execute requests in this order:
   ```
   1. /register → 2. /verify-email → 3. /login → 4. /mfa/setup → etc.
   ```

## Database Schema
Key tables:
```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  is_verified BOOLEAN DEFAULT FALSE,
  verification_token VARCHAR(255),
  mfa_secret VARCHAR(255),
  backup_codes TEXT[],
  failed_login_attempts INTEGER DEFAULT 0
);

CREATE TABLE refresh_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  token VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL
);
```

## Error Handling
Standard error responses:
```json
{
  "error": "Descriptive message",
  "details": "Additional context"  // Optional
}
```

Common status codes:
- `400` Bad Request
- `401` Unauthorized  
- `403` Forbidden (e.g., email not verified)
- `429` Too Many Requests

## Rate Limiting
- 100 requests per 15 minutes
- Lockout after 5 failed login attempts (30 minute lock)

## Security
- 🔒 All passwords hashed with bcrypt
- 🔑 JWT signed with HS256
- 🛡️ Helmet for HTTP header protection
- 🔄 Refresh token rotation
- 📧 Secure password reset flow
