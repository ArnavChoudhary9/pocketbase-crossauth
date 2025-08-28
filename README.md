# PocketBase Supabase Auth Integration

A Go-based PocketBase server that integrates with Supabase authentication, allowing seamless user authentication between Supabase and PocketBase systems.

## What it does

This project creates a bridge between Supabase authentication and PocketBase, enabling:

- **Automatic User Sync**: Automatically creates or updates PocketBase users based on Supabase JWT tokens
- **Token Validation**: Validates Supabase JWT tokens using JWKS (JSON Web Key Set)
- **Token Refresh**: Automatically refreshes expired access tokens using refresh tokens
- **Cookie-based Auth**: Reads Supabase auth tokens from HTTP cookies
- **Middleware Protection**: Global middleware that protects all routes except admin paths
- **User Management**: Maps Supabase user IDs to PocketBase users with proper verification

## Architecture

The system works by:
1. Reading Supabase auth tokens from cookies (`sb-{project-id}-auth-token`)
2. Validating JWT tokens against Supabase's JWKS endpoint
3. Creating/updating corresponding PocketBase user records
4. Setting authentication context for protected routes

## Prerequisites

- Go 1.19+
- PocketBase
- Supabase project with authentication enabled

## Installation

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd pocketbase
```

### 2. Install dependencies

```bash
go mod init pocketbase-supabase
go get github.com/pocketbase/pocketbase
go get github.com/golang-jwt/jwt/v5
go get github.com/joho/godotenv
```

### 3. Create PocketBase data directory

```bash
mkdir pb_data
```

### 4. Environment Configuration

Create a `.env` file in the project root:

```env
SUPABASE_PROJECT_ID=your_supabase_project_id
SUPABASE_ANON_KEY=your_supabase_anon_key
COOKIE_DOMAIN=localhost
```

**Required Variables:**
- `SUPABASE_PROJECT_ID`: Your Supabase project identifier
- `SUPABASE_ANON_KEY`: Your Supabase anonymous/public key
- `COOKIE_DOMAIN`: Domain for cookie handling (optional, defaults to request domain)

### 5. PocketBase Users Collection Setup

The application expects a `users` collection in PocketBase with the following fields:
- `email` (Email field)
- `username` (Text field)
- `password` (Password field)
- `user_id` (Text field) - stores Supabase user ID
- `verified` (Bool field)
- `emailVisibility` (Bool field)

## Development Build

### Build and run for development:

```bash
go run .
```

The server will start on `http://localhost:8090` by default.

### Development with auto-reload:

You can use tools like `air` for auto-reloading during development:

```bash
# Install air
go install github.com/cosmtrek/air@latest

# Run with auto-reload
air
```

## Production Build

### 1. Build the binary:

```bash
# For current platform
go build -o pocketbase-server .

# For Linux (if building on different OS)
GOOS=linux GOARCH=amd64 go build -o pocketbase-server .
```

### 2. Run in production:

```bash
./pocketbase-server serve --http=0.0.0.0:8090
```

### 3. Using systemd (Linux):

Create a systemd service file `/etc/systemd/system/pocketbase.service`:

```ini
[Unit]
Description=PocketBase Supabase Server
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/your/project
ExecStart=/path/to/your/project/pocketbase-server serve --http=0.0.0.0:8090
Restart=always
RestartSec=5
Environment=SUPABASE_PROJECT_ID=your_project_id
Environment=SUPABASE_ANON_KEY=your_anon_key
Environment=COOKIE_DOMAIN=yourdomain.com

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pocketbase
sudo systemctl start pocketbase
```

## API Endpoints

### Protected Routes

All routes are protected by default except:
- `/_/*` (PocketBase admin UI)
- `/favicon.ico`
- `/robots.txt`

### Authentication Endpoint

**POST** `/auth`
- Validates current Supabase session
- Returns PocketBase user info and Supabase claims
- Requires valid Supabase auth cookie

**Response:**
```json
{
  "record": {
    "id": "pb_user_id",
    "email": "user@example.com",
    "username": "username",
    "verified": true,
    "emailVisibility": true,
    "user_id": "supabase_user_id"
  },
  "supabase_claims": {
    "user_id": "supabase_user_id",
    "email": "user@example.com",
    "aud": "authenticated",
    "exp": 1234567890,
    "iss": "supabase"
  },
  "success": true
}
```

### Test Endpoint

**GET** `/whoami`
- Returns current authentication status and user info
- Useful for testing authentication flow

## File Structure

```
pocketbase/
├── main.go           # Main server and middleware logic
├── pbUser.go         # PocketBase user management functions
├── config.go         # Environment configuration
├── auth.go           # JWT verification and token refresh
├── pb_data/          # PocketBase data directory
├── .env              # Environment variables
├── go.mod            # Go module dependencies
└── README.md         # This file
```

## Key Features

### Automatic Token Refresh
The middleware automatically attempts to refresh expired access tokens using the refresh token from the cookie.

### User Synchronization
- Creates new PocketBase users for new Supabase users
- Updates existing users with Supabase user ID if missing
- Ensures all users are marked as verified

### Security
- Validates JWT signatures using Supabase's JWKS
- Protects all routes except admin paths
- Handles token expiration gracefully

## Troubleshooting

### Common Issues

1. **JWKS fetch failed**: Check your Supabase project ID and internet connection
2. **Authentication required**: Ensure Supabase auth cookie is present and valid
3. **Failed to get user**: Check PocketBase users collection schema
4. **Token refresh failed**: Verify Supabase anon key and project configuration

### Debugging

Enable detailed logging by checking the console output. The application logs:
- Authentication attempts
- Token validation results
- User creation/updates
- Token refresh operations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request
