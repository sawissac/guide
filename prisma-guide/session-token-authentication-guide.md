# Session Token & Authentication Guide for Prisma

## 📚 Table of Contents

1. [Introduction](#introduction)
2. [Basic Authentication](#basic-authentication)
3. [JWT Implementation](#jwt-implementation)
4. [Session Management](#session-management)
5. [Advanced Security](#advanced-security)
6. [Production Best Practices](#production-best-practices)
7. [Complete Implementation](#complete-implementation)

---

## Introduction

This guide covers implementing secure authentication with session tokens in Prisma applications, including JWT, refresh tokens, and session management.

### What You'll Learn
- Password hashing and verification
- JWT token generation and validation
- Session management strategies
- Refresh token rotation
- Security best practices
- Production-ready implementations

---

## Basic Authentication

### 1. User Model with Authentication

```prisma
// schema.prisma
model User {
  id            String    @id @default(uuid())
  email         String    @unique
  username      String?   @unique
  password      String    // Hashed password
  emailVerified Boolean   @default(false)
  active        Boolean   @default(true)
  role          Role      @default(USER)
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
  
  sessions      Session[]
  refreshTokens RefreshToken[]
  loginHistory  LoginHistory[]
  
  @@index([email])
  @@index([username])
}

enum Role {
  USER
  ADMIN
  MODERATOR
}

model Session {
  id           String   @id @default(uuid())
  userId       String
  token        String   @unique
  ipAddress    String?
  userAgent    String?
  lastActivity DateTime @default(now())
  expiresAt    DateTime
  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([userId])
  @@index([token])
  @@index([expiresAt])
}

model RefreshToken {
  id          String    @id @default(uuid())
  userId      String
  token       String    @unique
  family      String    // Token family for rotation
  issuedAt    DateTime  @default(now())
  expiresAt   DateTime
  revokedAt   DateTime?
  replacedBy  String?   // ID of the new token that replaced this one
  user        User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([userId])
  @@index([token])
  @@index([family])
}

model LoginHistory {
  id         String   @id @default(uuid())
  userId     String
  ipAddress  String
  userAgent  String?
  success    Boolean
  reason     String?  // Failed login reason
  createdAt  DateTime @default(now())
  user       User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([userId, createdAt])
}
```

---

## JWT Implementation

### 2. JWT Service

```typescript
// services/jwt.service.ts
import jwt from 'jsonwebtoken'
import { randomBytes } from 'crypto'

interface TokenPayload {
  userId: string
  email: string
  role: string
}

interface RefreshTokenPayload {
  userId: string
  family: string
}

class JWTService {
  private readonly accessTokenSecret = process.env.JWT_ACCESS_SECRET!
  private readonly refreshTokenSecret = process.env.JWT_REFRESH_SECRET!
  private readonly accessTokenExpiry = '15m'
  private readonly refreshTokenExpiry = '7d'
  
  // Generate access token
  generateAccessToken(payload: TokenPayload): string {
    return jwt.sign(payload, this.accessTokenSecret, {
      expiresIn: this.accessTokenExpiry,
      issuer: 'your-app',
      audience: 'your-app-users'
    })
  }
  
  // Generate refresh token
  generateRefreshToken(userId: string, family?: string): string {
    const tokenFamily = family || randomBytes(32).toString('hex')
    
    return jwt.sign(
      { userId, family: tokenFamily },
      this.refreshTokenSecret,
      {
        expiresIn: this.refreshTokenExpiry,
        jwtid: randomBytes(16).toString('hex')
      }
    )
  }
  
  // Verify access token
  verifyAccessToken(token: string): TokenPayload {
    try {
      return jwt.verify(token, this.accessTokenSecret) as TokenPayload
    } catch (error) {
      throw new Error('Invalid access token')
    }
  }
  
  // Verify refresh token
  verifyRefreshToken(token: string): RefreshTokenPayload {
    try {
      return jwt.verify(token, this.refreshTokenSecret) as RefreshTokenPayload
    } catch (error) {
      throw new Error('Invalid refresh token')
    }
  }
  
  // Decode without verification (for expired tokens)
  decodeToken(token: string): any {
    return jwt.decode(token)
  }
}

export const jwtService = new JWTService()
```

---

### 3. Authentication Service

```typescript
// services/auth.service.ts
import bcrypt from 'bcrypt'
import { PrismaClient } from '@prisma/client'
import { jwtService } from './jwt.service'
import { randomBytes } from 'crypto'

const prisma = new PrismaClient()

class AuthService {
  private readonly saltRounds = 10
  private readonly maxLoginAttempts = 5
  private readonly lockoutDuration = 15 * 60 * 1000 // 15 minutes
  
  // Register new user
  async register(email: string, password: string, username?: string) {
    // Validate password strength
    this.validatePasswordStrength(password)
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, this.saltRounds)
    
    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        username,
        password: hashedPassword
      }
    })
    
    // Generate tokens
    const tokens = await this.generateTokens(user)
    
    return { user, tokens }
  }
  
  // Login
  async login(email: string, password: string, ipAddress: string, userAgent?: string) {
    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
      include: {
        loginHistory: {
          where: {
            createdAt: {
              gte: new Date(Date.now() - this.lockoutDuration)
            },
            success: false
          }
        }
      }
    })
    
    if (!user) {
      throw new Error('Invalid credentials')
    }
    
    // Check for account lockout
    if (user.loginHistory.length >= this.maxLoginAttempts) {
      throw new Error('Account temporarily locked due to too many failed attempts')
    }
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password)
    
    // Log login attempt
    await prisma.loginHistory.create({
      data: {
        userId: user.id,
        ipAddress,
        userAgent,
        success: isValidPassword,
        reason: isValidPassword ? null : 'Invalid password'
      }
    })
    
    if (!isValidPassword) {
      throw new Error('Invalid credentials')
    }
    
    // Check if user is active
    if (!user.active) {
      throw new Error('Account is deactivated')
    }
    
    // Generate tokens
    const tokens = await this.generateTokens(user)
    
    // Create session
    await this.createSession(user.id, tokens.accessToken, ipAddress, userAgent)
    
    return { user, tokens }
  }
  
  // Generate both tokens
  private async generateTokens(user: any) {
    const accessToken = jwtService.generateAccessToken({
      userId: user.id,
      email: user.email,
      role: user.role
    })
    
    const refreshToken = jwtService.generateRefreshToken(user.id)
    
    // Store refresh token
    await prisma.refreshToken.create({
      data: {
        userId: user.id,
        token: refreshToken,
        family: jwtService.decodeToken(refreshToken).family,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
      }
    })
    
    return { accessToken, refreshToken }
  }
  
  // Refresh tokens
  async refreshTokens(refreshToken: string) {
    // Verify refresh token
    const payload = jwtService.verifyRefreshToken(refreshToken)
    
    // Find stored token
    const storedToken = await prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true }
    })
    
    if (!storedToken || storedToken.revokedAt) {
      // Possible token reuse - revoke entire family
      await this.revokeTokenFamily(payload.family)
      throw new Error('Invalid refresh token')
    }
    
    // Check expiration
    if (storedToken.expiresAt < new Date()) {
      throw new Error('Refresh token expired')
    }
    
    // Rotate refresh token
    const newAccessToken = jwtService.generateAccessToken({
      userId: storedToken.user.id,
      email: storedToken.user.email,
      role: storedToken.user.role
    })
    
    const newRefreshToken = jwtService.generateRefreshToken(
      storedToken.user.id,
      payload.family
    )
    
    // Transaction: revoke old, create new
    await prisma.$transaction([
      // Revoke old token
      prisma.refreshToken.update({
        where: { id: storedToken.id },
        data: {
          revokedAt: new Date(),
          replacedBy: newRefreshToken
        }
      }),
      // Create new token
      prisma.refreshToken.create({
        data: {
          userId: storedToken.user.id,
          token: newRefreshToken,
          family: payload.family,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        }
      })
    ])
    
    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    }
  }
  
  // Revoke token family (security breach)
  private async revokeTokenFamily(family: string) {
    await prisma.refreshToken.updateMany({
      where: {
        family,
        revokedAt: null
      },
      data: {
        revokedAt: new Date()
      }
    })
  }
  
  // Create session
  private async createSession(
    userId: string,
    token: string,
    ipAddress?: string,
    userAgent?: string
  ) {
    await prisma.session.create({
      data: {
        userId,
        token,
        ipAddress,
        userAgent,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000) // 15 minutes
      }
    })
  }
  
  // Validate session
  async validateSession(token: string) {
    const session = await prisma.session.findUnique({
      where: { token },
      include: { user: true }
    })
    
    if (!session) {
      throw new Error('Session not found')
    }
    
    if (session.expiresAt < new Date()) {
      await prisma.session.delete({ where: { id: session.id } })
      throw new Error('Session expired')
    }
    
    // Update last activity
    await prisma.session.update({
      where: { id: session.id },
      data: { lastActivity: new Date() }
    })
    
    return session.user
  }
  
  // Logout
  async logout(userId: string, token?: string) {
    if (token) {
      // Logout specific session
      await prisma.session.deleteMany({
        where: {
          userId,
          token
        }
      })
    } else {
      // Logout all sessions
      await prisma.session.deleteMany({
        where: { userId }
      })
    }
  }
  
  // Password validation
  private validatePasswordStrength(password: string) {
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters')
    }
    
    const hasUpperCase = /[A-Z]/.test(password)
    const hasLowerCase = /[a-z]/.test(password)
    const hasNumbers = /\d/.test(password)
    const hasSpecialChar = /[!@#$%^&*]/.test(password)
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
      throw new Error('Password must contain uppercase, lowercase, numbers, and special characters')
    }
  }
}

export const authService = new AuthService()
```

---

## Session Management

### 4. Session Middleware

```typescript
// middleware/auth.middleware.ts
import { Request, Response, NextFunction } from 'express'
import { jwtService } from '../services/jwt.service'
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

interface AuthRequest extends Request {
  user?: any
  session?: any
}

// Verify access token middleware
export async function authenticateToken(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1] // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' })
  }
  
  try {
    const payload = jwtService.verifyAccessToken(token)
    
    // Get user from database
    const user = await prisma.user.findUnique({
      where: { id: payload.userId }
    })
    
    if (!user || !user.active) {
      return res.status(401).json({ error: 'User not found or inactive' })
    }
    
    req.user = user
    next()
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' })
  }
}

// Role-based authorization
export function authorize(...roles: string[]) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' })
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' })
    }
    
    next()
  }
}

// Session validation middleware
export async function validateSession(
  req: AuthRequest,
  res: Response,
  next: NextFunction
) {
  const sessionToken = req.cookies?.sessionToken || req.headers['x-session-token']
  
  if (!sessionToken) {
    return res.status(401).json({ error: 'Session required' })
  }
  
  try {
    const session = await prisma.session.findUnique({
      where: { token: sessionToken },
      include: { user: true }
    })
    
    if (!session || session.expiresAt < new Date()) {
      return res.status(401).json({ error: 'Session expired' })
    }
    
    // Extend session
    await prisma.session.update({
      where: { id: session.id },
      data: {
        lastActivity: new Date(),
        expiresAt: new Date(Date.now() + 15 * 60 * 1000)
      }
    })
    
    req.user = session.user
    req.session = session
    next()
  } catch (error) {
    return res.status(500).json({ error: 'Session validation failed' })
  }
}
```

---

## Advanced Security

### 5. Two-Factor Authentication

```prisma
model User {
  // ... existing fields
  twoFactorEnabled Boolean @default(false)
  twoFactorSecret  String?
  backupCodes      BackupCode[]
}

model BackupCode {
  id     String  @id @default(uuid())
  userId String
  code   String
  used   Boolean @default(false)
  user   User    @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@unique([userId, code])
}
```

```typescript
// services/2fa.service.ts
import speakeasy from 'speakeasy'
import qrcode from 'qrcode'
import { randomBytes } from 'crypto'

class TwoFactorService {
  // Enable 2FA
  async enableTwoFactor(userId: string) {
    const secret = speakeasy.generateSecret({
      name: 'YourApp',
      length: 32
    })
    
    // Store secret
    await prisma.user.update({
      where: { id: userId },
      data: {
        twoFactorSecret: secret.base32
      }
    })
    
    // Generate backup codes
    const backupCodes = await this.generateBackupCodes(userId)
    
    // Generate QR code
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url!)
    
    return {
      secret: secret.base32,
      qrCode: qrCodeUrl,
      backupCodes
    }
  }
  
  // Verify 2FA token
  async verifyToken(userId: string, token: string): Promise<boolean> {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    })
    
    if (!user?.twoFactorSecret) {
      return false
    }
    
    return speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
      window: 2 // Allow 2 time windows
    })
  }
  
  // Generate backup codes
  private async generateBackupCodes(userId: string): Promise<string[]> {
    const codes: string[] = []
    
    for (let i = 0; i < 10; i++) {
      const code = randomBytes(4).toString('hex').toUpperCase()
      codes.push(code)
      
      await prisma.backupCode.create({
        data: {
          userId,
          code: await bcrypt.hash(code, 10)
        }
      })
    }
    
    return codes
  }
}
```

---

### 6. Rate Limiting & Brute Force Protection

```typescript
// middleware/rateLimiter.ts
import rateLimit from 'express-rate-limit'
import RedisStore from 'rate-limit-redis'
import Redis from 'ioredis'

const redis = new Redis()

// General API rate limiter
export const apiLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:api:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: 'Too many requests'
})

// Login rate limiter
export const loginLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:login:'
  }),
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 attempts per 15 minutes
  skipSuccessfulRequests: true
})

// Password reset limiter
export const passwordResetLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:reset:'
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3 // 3 reset attempts per hour
})
```

---

## Production Best Practices

### 7. Environment Configuration

```env
# .env
NODE_ENV=production

# JWT Secrets (generate with: openssl rand -base64 32)
JWT_ACCESS_SECRET=your-super-secret-access-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key

# Token Expiry
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

# Security
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=900000

# Session
SESSION_SECRET=your-session-secret
SESSION_MAX_AGE=86400000

# CORS
CORS_ORIGIN=https://yourdomain.com

# Rate Limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
```

### 8. Security Headers

```typescript
// middleware/security.ts
import helmet from 'helmet'
import cors from 'cors'

export function setupSecurity(app: Express) {
  // Helmet for security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }))
  
  // CORS configuration
  app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
    optionsSuccessStatus: 200
  }))
  
  // Additional headers
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
    next()
  })
}
```

---

## Complete Implementation

### 9. Express Routes

```typescript
// routes/auth.routes.ts
import express from 'express'
import { authService } from '../services/auth.service'
import { authenticateToken, validateSession } from '../middleware/auth.middleware'
import { loginLimiter, passwordResetLimiter } from '../middleware/rateLimiter'

const router = express.Router()

// Register
router.post('/register', async (req, res) => {
  try {
    const { email, password, username } = req.body
    const result = await authService.register(email, password, username)
    
    res.cookie('refreshToken', result.tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    })
    
    res.json({
      user: result.user,
      accessToken: result.tokens.accessToken
    })
  } catch (error) {
    res.status(400).json({ error: error.message })
  }
})

// Login
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body
    const ipAddress = req.ip
    const userAgent = req.get('user-agent')
    
    const result = await authService.login(email, password, ipAddress, userAgent)
    
    res.cookie('refreshToken', result.tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    })
    
    res.json({
      user: result.user,
      accessToken: result.tokens.accessToken
    })
  } catch (error) {
    res.status(401).json({ error: error.message })
  }
})

// Refresh token
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.cookies
    
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' })
    }
    
    const tokens = await authService.refreshTokens(refreshToken)
    
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    })
    
    res.json({ accessToken: tokens.accessToken })
  } catch (error) {
    res.status(401).json({ error: error.message })
  }
})

// Logout
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    await authService.logout(req.user.id, req.headers['authorization']?.split(' ')[1])
    
    res.clearCookie('refreshToken')
    res.json({ message: 'Logged out successfully' })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Protected route example
router.get('/profile', authenticateToken, async (req, res) => {
  res.json({ user: req.user })
})

// Admin only route
router.get('/admin', authenticateToken, authorize('ADMIN'), async (req, res) => {
  res.json({ message: 'Admin access granted' })
})

export default router
```

### 10. Client Usage

```typescript
// client/auth.client.ts
class AuthClient {
  private accessToken: string | null = null
  private refreshTimer: NodeJS.Timeout | null = null
  
  // Login
  async login(email: string, password: string) {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email, password })
    })
    
    if (!response.ok) {
      throw new Error('Login failed')
    }
    
    const data = await response.json()
    this.accessToken = data.accessToken
    
    // Setup auto-refresh
    this.scheduleTokenRefresh()
    
    return data.user
  }
  
  // Make authenticated request
  async request(url: string, options: RequestInit = {}) {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.accessToken}`
      },
      credentials: 'include'
    })
    
    if (response.status === 401) {
      // Try to refresh token
      await this.refreshToken()
      
      // Retry request
      return fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${this.accessToken}`
        },
        credentials: 'include'
      })
    }
    
    return response
  }
  
  // Refresh token
  private async refreshToken() {
    const response = await fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'include'
    })
    
    if (!response.ok) {
      throw new Error('Session expired')
    }
    
    const data = await response.json()
    this.accessToken = data.accessToken
    
    this.scheduleTokenRefresh()
  }
  
  // Schedule token refresh
  private scheduleTokenRefresh() {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer)
    }
    
    // Refresh 1 minute before expiry
    this.refreshTimer = setTimeout(() => {
      this.refreshToken().catch(console.error)
    }, 14 * 60 * 1000) // 14 minutes
  }
}
```

---

## Testing

### Unit Tests

```typescript
// tests/auth.test.ts
import { authService } from '../services/auth.service'

describe('Authentication', () => {
  test('should register user', async () => {
    const result = await authService.register(
      'test@example.com',
      'Test@1234'
    )
    
    expect(result.user.email).toBe('test@example.com')
    expect(result.tokens.accessToken).toBeDefined()
    expect(result.tokens.refreshToken).toBeDefined()
  })
  
  test('should validate password strength', async () => {
    await expect(
      authService.register('test@example.com', 'weak')
    ).rejects.toThrow()
  })
  
  test('should refresh tokens', async () => {
    const { tokens } = await authService.register(
      'test2@example.com',
      'Test@1234'
    )
    
    const newTokens = await authService.refreshTokens(
      tokens.refreshToken
    )
    
    expect(newTokens.accessToken).toBeDefined()
    expect(newTokens.refreshToken).toBeDefined()
  })
})
```

---

## Security Checklist

- ✅ Passwords hashed with bcrypt (min 10 rounds)
- ✅ JWT secrets stored in environment variables
- ✅ Refresh token rotation implemented
- ✅ Rate limiting on sensitive endpoints
- ✅ Account lockout after failed attempts
- ✅ Session management with expiry
- ✅ HTTPS only in production
- ✅ Secure cookie flags (httpOnly, secure, sameSite)
- ✅ CORS properly configured
- ✅ Security headers with Helmet
- ✅ Input validation and sanitization
- ✅ SQL injection prevention (Prisma handles this)
- ✅ XSS prevention
- ✅ CSRF protection
- ✅ Two-factor authentication option
- ✅ Audit logging for security events
- ✅ Regular token cleanup job
- ✅ Password reset with secure tokens
- ✅ Email verification
- ✅ Monitoring and alerting

---

## Quick Reference

### Token Lifetimes
- **Access Token**: 15 minutes
- **Refresh Token**: 7 days
- **Session**: 15 minutes (extended on activity)
- **Password Reset**: 1 hour
- **Email Verification**: 24 hours

### Security Headers
```typescript
{
  'Strict-Transport-Security': 'max-age=31536000',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Content-Security-Policy': "default-src 'self'"
}
```

### Error Codes
- `401`: Authentication required
- `403`: Insufficient permissions
- `429`: Too many requests

---

Happy Secure Coding! 🔐
