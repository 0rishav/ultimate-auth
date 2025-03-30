# Ultimate Auth

A simple JWT-based authentication system with access & refresh tokens.

# Installation
```sh
npm install ultimate-auth
```

# Usage

## Setup the Auth System

```ts
import Auth from "your-auth-package";
import { TokenStorage } from "./your-token-storage-implementation";

// Define Secrets and Expiry Durations
const auth = new Auth(
  process.env.ACCESS_SECRET!,
  process.env.REFRESH_SECRET!,
  new TokenStorage(), // You need to implement this
  "15m", // Access Token Expiry
  "3d"  // Refresh Token Expiry
);
```

# Methods & Examples

## 1. Generate Access & Refresh Token

```ts
import { Request, Response } from "express";

// Login API
app.post("/login", async (req: Request, res: Response) => {
  const { email, password } = req.body;

  // 🔎 Find User in Database
  const user = await User.findOne({ email });

  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Invalid email or password" });
  }

  // Generate Access & Refresh Tokens
  const tokens = await auth.generateAccessAndRefreshToken(user, res);

  res.json({ message: "Login successful!", tokens });
});
```
## What it does?

- Finds the user

- Verifies password

- Generates Access & Refresh Tokens

- Stores tokens securely in HTTP-only cookies

## 2. Verify Access Token

```ts
app.get("/protected", async (req: Request, res: Response) => {
  const isAuthenticated = await auth.authenticate(req, res);
  if (!isAuthenticated) return;

  res.json({ message: "You are authenticated!" });
});
```

## What it does?

- Reads accessToken from cookies

- Verifies & Decodes JWT

- If valid, request continues

- If invalid/expired/revoked, returns 401 Unauthorized

## 3. Verify Refresh Token

```ts
app.post("/refresh-token", async (req: Request, res: Response) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh Token Missing!" });
  }

  const user = await User.findOne({ refreshToken: auth.hashToken(refreshToken) });

  if (!user || !(await auth.verifyRefreshToken(refreshToken, user.refreshToken))) {
    return res.status(403).json({ message: "Invalid Refresh Token!" });
  }

  // Generate new tokens
  const tokens = await auth.generateAccessAndRefreshToken(user, res);

  res.json({ message: "Tokens refreshed!", tokens });
});
```

## What it does?

- Takes refreshToken from HTTP-only cookie

- Checks if it matches hashed version in DB

- If valid, issues new tokens

- Else, 403 Forbidden

## 4. Logout & Revoke Tokens

```ts
app.post("/logout", async (req: Request, res: Response) => {
  const { refreshToken } = req.cookies;

  await auth.logout(res, refreshToken);

  res.json({ message: "Logged out successfully!" });
});
```

## What it does?

- Revokes refresh token (stores in revoked list)

- Clears accessToken & refreshToken from cookies

- Token Management Functions

## 5. Generate Token (Internal)

```ts
private generateToken(userId: string, secret: string, expiresIn: string);
```
- Creates JWT with User ID & JTI (unique identifier)

## 6. Set Cookie (Internal)

```ts
private setCookie(res: ServerResponse, name: string, value: string, options: CookieOptions);
```
- Stores tokens securely in HTTP-only cookies

🔹 7. Verify Token (Internal)

```ts
private async verifyToken(token: string, secret: string);
```
- Decodes & validates JWT, checks revocation

## 8. Revoke Token

```ts
async revokeToken(token: string);
```
- Marks refresh token as revoked

# Example API Endpoints

| Method | Endpoint       | Description                            |
|--------|--------------|----------------------------------------|
| POST   | `/login`     | Authenticate user & generate tokens   |
| GET    | `/protected` | Verify access token & authenticate user |
| POST   | `/refresh-token` | Refresh expired access token       |
| POST   | `/logout`    | Logout & revoke refresh token         |


# Security Measures

- JWT is signed using HS256
- Refresh Tokens are hashed in DB
- HTTP-Only Cookies prevent XSS attacks
- Token Revocation prevents token reuse
- Secure, SameSite & HttpOnly flags enabled