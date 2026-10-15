# E-commerce Auth System (Node/Express + MongoDB + React)

Email-OTP registration, JWT access token (memory) + rotating opaque refresh token (HttpOnly cookie),
logout, logout-all-devices, session list/revoke, password reset/change, rate limiting, audit log.

## Run the backend
    cd backend
    cp .env.example .env      # then generate real secrets (command inside the file)
    npm install
    npm run dev               # needs a running MongoDB (MONGO_URI)

In development, emails (with the OTP) are printed in the server console.

## Frontend
Copy `frontend/src` files into your Vite + React app, install `axios react-router-dom`,
set `VITE_API_URL`, wrap your app in <AuthProvider>.

## Production minimum
HTTPS everywhere, TRUST_PROXY set correctly, real SMTP, Redis-backed rate limiting,
MongoDB with auth + TLS + backups, secrets in a secret manager. See the PDF checklist.
