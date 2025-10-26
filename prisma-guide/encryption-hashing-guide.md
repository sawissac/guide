# Password Hashing & Data Encryption Guide for Prisma

## 📚 Table of Contents

1. [Important Security Concepts](#important-security-concepts)
2. [Password Hashing (One-Way)](#password-hashing-one-way)
3. [Data Encryption (Two-Way)](#data-encryption-two-way)
4. [Field-Level Encryption in Prisma](#field-level-encryption-in-prisma)
5. [Complete Implementation](#complete-implementation)
6. [Security Best Practices](#security-best-practices)

---

## Important Security Concepts

### ⚠️ Critical Distinction

**Passwords**: Should NEVER be encrypted (reversible). Always use one-way hashing.
**Sensitive Data**: Can be encrypted when you need to retrieve the original value.

```typescript
// ❌ NEVER DO THIS - Don't encrypt passwords
const encryptedPassword = encrypt(password)  // BAD!
const decryptedPassword = decrypt(encryptedPassword)  // NEVER!

// ✅ CORRECT - Hash passwords (one-way)
const hashedPassword = await bcrypt.hash(password, 10)  // GOOD!
const isValid = await bcrypt.compare(plainPassword, hashedPassword)  // GOOD!

// ✅ CORRECT - Encrypt sensitive data that needs retrieval
const encryptedSSN = encrypt(socialSecurityNumber)  // OK for sensitive data
const decryptedSSN = decrypt(encryptedSSN)  // OK when needed
```

---

## Password Hashing (One-Way)

### 1. Basic Password Hashing with bcrypt

```typescript
// services/password.service.ts
import bcrypt from 'bcrypt'
import argon2 from 'argon2'
import crypto from 'crypto'

class PasswordService {
  private readonly BCRYPT_ROUNDS = 12
  private readonly MIN_PASSWORD_LENGTH = 8
  private readonly MAX_PASSWORD_LENGTH = 128
  
  // Hash password with bcrypt
  async hashPassword(password: string): Promise<string> {
    this.validatePassword(password)
    return bcrypt.hash(password, this.BCRYPT_ROUNDS)
  }
  
  // Verify password with bcrypt
  async verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword)
  }
  
  // Alternative: Hash with Argon2 (more secure, recommended for new projects)
  async hashPasswordArgon2(password: string): Promise<string> {
    this.validatePassword(password)
    
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,  // 64 MB
      timeCost: 3,
      parallelism: 1,
    })
  }
  
  // Verify with Argon2
  async verifyPasswordArgon2(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return argon2.verify(hashedPassword, plainPassword)
  }
  
  // Password strength validation
  private validatePassword(password: string): void {
    if (password.length < this.MIN_PASSWORD_LENGTH) {
      throw new Error(`Password must be at least ${this.MIN_PASSWORD_LENGTH} characters`)
    }
    
    if (password.length > this.MAX_PASSWORD_LENGTH) {
      throw new Error(`Password must be less than ${this.MAX_PASSWORD_LENGTH} characters`)
    }
    
    const requirements = [
      { regex: /[A-Z]/, message: 'Password must contain uppercase letter' },
      { regex: /[a-z]/, message: 'Password must contain lowercase letter' },
      { regex: /\d/, message: 'Password must contain number' },
      { regex: /[!@#$%^&*(),.?":{}|<>]/, message: 'Password must contain special character' }
    ]
    
    for (const req of requirements) {
      if (!req.regex.test(password)) {
        throw new Error(req.message)
      }
    }
  }
  
  // Check if password needs rehashing (upgrade security)
  needsRehash(hashedPassword: string): boolean {
    // Check if using old algorithm or rounds
    const match = hashedPassword.match(/^\$2[ayb]\$(\d+)\$/)
    if (match) {
      const rounds = parseInt(match[1])
      return rounds < this.BCRYPT_ROUNDS
    }
    return false
  }
  
  // Generate secure random password
  generateSecurePassword(length: number = 16): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'
    let password = ''
    const randomBytes = crypto.randomBytes(length)
    
    for (let i = 0; i < length; i++) {
      password += charset[randomBytes[i] % charset.length]
    }
    
    return password
  }
}

export const passwordService = new PasswordService()
```

### 2. Prisma Schema for Password Storage

```prisma
model User {
  id                String    @id @default(uuid())
  email             String    @unique
  passwordHash      String    // Never store plain passwords!
  passwordChangedAt DateTime? // Track password changes
  passwordResetToken String?  // For password reset
  passwordResetExpires DateTime?
  
  // Security tracking
  failedLoginAttempts Int      @default(0)
  lockedUntil       DateTime?
  lastLoginAt       DateTime?
  lastLoginIp       String?
  
  @@index([email])
  @@index([passwordResetToken])
}

model PasswordHistory {
  id           String   @id @default(uuid())
  userId       String
  passwordHash String   // Store old password hashes
  createdAt    DateTime @default(now())
  user         User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([userId, createdAt])
}
```

### 3. Authentication Service with Hashing

```typescript
// services/auth.service.ts
import { PrismaClient } from '@prisma/client'
import { passwordService } from './password.service'
import crypto from 'crypto'

const prisma = new PrismaClient()

class AuthenticationService {
  // Register with hashed password
  async register(email: string, password: string) {
    // Hash the password
    const passwordHash = await passwordService.hashPassword(password)
    
    // Create user with hashed password
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        passwordChangedAt: new Date()
      }
    })
    
    // Store in password history
    await prisma.passwordHistory.create({
      data: {
        userId: user.id,
        passwordHash
      }
    })
    
    return user
  }
  
  // Login with password verification
  async login(email: string, password: string, ipAddress?: string) {
    const user = await prisma.user.findUnique({
      where: { email }
    })
    
    if (!user) {
      throw new Error('Invalid credentials')
    }
    
    // Check if account is locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      throw new Error('Account is locked. Please try again later.')
    }
    
    // Verify password
    const isValidPassword = await passwordService.verifyPassword(
      password,
      user.passwordHash
    )
    
    if (!isValidPassword) {
      // Increment failed attempts
      await this.handleFailedLogin(user.id)
      throw new Error('Invalid credentials')
    }
    
    // Check if password needs rehashing
    if (passwordService.needsRehash(user.passwordHash)) {
      const newHash = await passwordService.hashPassword(password)
      await prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: newHash }
      })
    }
    
    // Reset failed attempts and update login info
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
        lastLoginAt: new Date(),
        lastLoginIp: ipAddress
      }
    })
    
    return user
  }
  
  // Handle failed login attempts
  private async handleFailedLogin(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    })
    
    if (!user) return
    
    const attempts = user.failedLoginAttempts + 1
    const maxAttempts = 5
    
    const updateData: any = {
      failedLoginAttempts: attempts
    }
    
    // Lock account after max attempts
    if (attempts >= maxAttempts) {
      updateData.lockedUntil = new Date(Date.now() + 30 * 60 * 1000) // 30 minutes
    }
    
    await prisma.user.update({
      where: { id: userId },
      data: updateData
    })
  }
  
  // Change password
  async changePassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        passwordHistory: {
          orderBy: { createdAt: 'desc' },
          take: 5 // Check last 5 passwords
        }
      }
    })
    
    if (!user) {
      throw new Error('User not found')
    }
    
    // Verify old password
    const isValid = await passwordService.verifyPassword(oldPassword, user.passwordHash)
    if (!isValid) {
      throw new Error('Current password is incorrect')
    }
    
    // Check password history (prevent reuse)
    const newPasswordHash = await passwordService.hashPassword(newPassword)
    
    for (const history of user.passwordHistory) {
      const isReused = await passwordService.verifyPassword(newPassword, history.passwordHash)
      if (isReused) {
        throw new Error('Password has been used recently. Please choose a different password.')
      }
    }
    
    // Update password
    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: {
          passwordHash: newPasswordHash,
          passwordChangedAt: new Date()
        }
      }),
      prisma.passwordHistory.create({
        data: {
          userId,
          passwordHash: newPasswordHash
        }
      })
    ])
  }
  
  // Password reset
  async requestPasswordReset(email: string) {
    const user = await prisma.user.findUnique({
      where: { email }
    })
    
    if (!user) {
      // Don't reveal if user exists
      return { message: 'If an account exists, a reset email has been sent' }
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex')
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex')
    
    // Save hashed token
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: hashedToken,
        passwordResetExpires: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
      }
    })
    
    // Return unhashed token for email
    return { resetToken, email: user.email }
  }
  
  // Reset password with token
  async resetPassword(token: string, newPassword: string) {
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex')
    
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: hashedToken,
        passwordResetExpires: { gt: new Date() }
      }
    })
    
    if (!user) {
      throw new Error('Invalid or expired reset token')
    }
    
    const passwordHash = await passwordService.hashPassword(newPassword)
    
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash,
        passwordChangedAt: new Date(),
        passwordResetToken: null,
        passwordResetExpires: null,
        failedLoginAttempts: 0,
        lockedUntil: null
      }
    })
  }
}
```

---

## Data Encryption (Two-Way)

### 4. Encryption Service for Sensitive Data

```typescript
// services/encryption.service.ts
import crypto from 'crypto'

class EncryptionService {
  private readonly algorithm = 'aes-256-gcm'
  private readonly keyLength = 32
  private readonly ivLength = 16
  private readonly tagLength = 16
  private readonly saltLength = 64
  private readonly iterations = 100000
  
  private masterKey: Buffer
  
  constructor() {
    // Load master key from environment
    const key = process.env.ENCRYPTION_MASTER_KEY
    if (!key) {
      throw new Error('ENCRYPTION_MASTER_KEY not set')
    }
    this.masterKey = Buffer.from(key, 'hex')
  }
  
  // Encrypt data
  encrypt(text: string): string {
    const iv = crypto.randomBytes(this.ivLength)
    const salt = crypto.randomBytes(this.saltLength)
    
    // Derive key from master key and salt
    const key = crypto.pbkdf2Sync(this.masterKey, salt, this.iterations, this.keyLength, 'sha256')
    
    const cipher = crypto.createCipheriv(this.algorithm, key, iv)
    
    const encrypted = Buffer.concat([
      cipher.update(text, 'utf8'),
      cipher.final()
    ])
    
    const tag = cipher.getAuthTag()
    
    // Combine salt, iv, tag, and encrypted data
    const combined = Buffer.concat([
      salt,
      iv,
      tag,
      encrypted
    ])
    
    return combined.toString('base64')
  }
  
  // Decrypt data
  decrypt(encryptedData: string): string {
    const buffer = Buffer.from(encryptedData, 'base64')
    
    // Extract components
    const salt = buffer.slice(0, this.saltLength)
    const iv = buffer.slice(this.saltLength, this.saltLength + this.ivLength)
    const tag = buffer.slice(this.saltLength + this.ivLength, this.saltLength + this.ivLength + this.tagLength)
    const encrypted = buffer.slice(this.saltLength + this.ivLength + this.tagLength)
    
    // Derive key from master key and salt
    const key = crypto.pbkdf2Sync(this.masterKey, salt, this.iterations, this.keyLength, 'sha256')
    
    const decipher = crypto.createDecipheriv(this.algorithm, key, iv)
    decipher.setAuthTag(tag)
    
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ])
    
    return decrypted.toString('utf8')
  }
  
  // Encrypt JSON object
  encryptObject(obj: any): string {
    return this.encrypt(JSON.stringify(obj))
  }
  
  // Decrypt JSON object
  decryptObject<T>(encryptedData: string): T {
    return JSON.parse(this.decrypt(encryptedData))
  }
  
  // Generate data encryption key
  generateDataKey(): { plaintext: string; encrypted: string } {
    const dataKey = crypto.randomBytes(32)
    const encrypted = this.encrypt(dataKey.toString('hex'))
    
    return {
      plaintext: dataKey.toString('hex'),
      encrypted
    }
  }
  
  // Hash data (for searching encrypted fields)
  hashForSearch(text: string): string {
    return crypto
      .createHmac('sha256', this.masterKey)
      .update(text)
      .digest('hex')
  }
}

export const encryptionService = new EncryptionService()
```

---

## Field-Level Encryption in Prisma

### 5. Prisma Schema with Encrypted Fields

```prisma
model User {
  id              String   @id @default(uuid())
  email           String   @unique
  emailHash       String?  // For searching encrypted email
  passwordHash    String   // Never decrypt!
  
  // Encrypted sensitive data
  ssnEncrypted    String?  // Social Security Number
  ssnHash         String?  // For searching
  
  phoneEncrypted  String?  // Phone number
  phoneHash       String?  // For searching
  
  // Medical/Financial data
  medicalRecords  Json?    @db.JsonB // Encrypted JSON
  creditCard      String?  // Encrypted
  bankAccount     String?  // Encrypted
  
  createdAt       DateTime @default(now())
  updatedAt       DateTime @updatedAt
  
  @@index([emailHash])
  @@index([ssnHash])
  @@index([phoneHash])
}

model EncryptionKey {
  id         String   @id @default(uuid())
  keyType    String   // 'user', 'medical', 'financial'
  keyId      String   @unique
  encrypted  String   // Encrypted data key
  version    Int      @default(1)
  active     Boolean  @default(true)
  createdAt  DateTime @default(now())
  rotatedAt  DateTime?
  
  @@index([keyType, active])
}
```

### 6. Prisma Middleware for Automatic Encryption

```typescript
// middleware/encryption.middleware.ts
import { PrismaClient } from '@prisma/client'
import { encryptionService } from '../services/encryption.service'

const prisma = new PrismaClient()

// Fields to automatically encrypt
const ENCRYPTED_FIELDS = {
  User: ['ssnEncrypted', 'phoneEncrypted', 'creditCard', 'bankAccount'],
  // Add other models and fields
}

// Searchable encrypted fields (need hash)
const SEARCHABLE_FIELDS = {
  User: {
    ssnEncrypted: 'ssnHash',
    phoneEncrypted: 'phoneHash'
  }
}

// Middleware for automatic encryption/decryption
prisma.$use(async (params, next) => {
  // Before create/update: encrypt
  if (params.action === 'create' || params.action === 'update') {
    const fields = ENCRYPTED_FIELDS[params.model as string]
    
    if (fields && params.args.data) {
      for (const field of fields) {
        if (params.args.data[field]) {
          // Encrypt the field
          params.args.data[field] = encryptionService.encrypt(params.args.data[field])
          
          // Add search hash if needed
          const hashField = SEARCHABLE_FIELDS[params.model as string]?.[field]
          if (hashField) {
            params.args.data[hashField] = encryptionService.hashForSearch(
              params.args.data[field]
            )
          }
        }
      }
    }
  }
  
  const result = await next(params)
  
  // After query: decrypt
  if (result && (params.action === 'findUnique' || params.action === 'findFirst' || params.action === 'findMany')) {
    const fields = ENCRYPTED_FIELDS[params.model as string]
    
    if (fields) {
      const decryptRecord = (record: any) => {
        if (!record) return record
        
        for (const field of fields) {
          if (record[field]) {
            try {
              record[field] = encryptionService.decrypt(record[field])
            } catch (error) {
              console.error(`Failed to decrypt ${field}:`, error)
              record[field] = null
            }
          }
        }
        return record
      }
      
      if (Array.isArray(result)) {
        return result.map(decryptRecord)
      } else {
        return decryptRecord(result)
      }
    }
  }
  
  return result
})
```

### 7. Key Rotation Service

```typescript
// services/keyRotation.service.ts
class KeyRotationService {
  // Rotate encryption keys
  async rotateKeys() {
    const users = await prisma.user.findMany({
      where: {
        OR: [
          { ssnEncrypted: { not: null } },
          { creditCard: { not: null } }
        ]
      }
    })
    
    for (const user of users) {
      // Re-encrypt with new key
      if (user.ssnEncrypted) {
        const decrypted = encryptionService.decrypt(user.ssnEncrypted)
        const reencrypted = encryptionService.encrypt(decrypted)
        
        await prisma.user.update({
          where: { id: user.id },
          data: { ssnEncrypted: reencrypted }
        })
      }
    }
    
    console.log(`Rotated keys for ${users.length} users`)
  }
  
  // Scheduled key rotation
  scheduleKeyRotation() {
    // Run monthly
    setInterval(() => {
      this.rotateKeys().catch(console.error)
    }, 30 * 24 * 60 * 60 * 1000)
  }
}
```

---

## Complete Implementation

### 8. Express API with Encryption

```typescript
// routes/user.routes.ts
import express from 'express'
import { passwordService } from '../services/password.service'
import { encryptionService } from '../services/encryption.service'

const router = express.Router()

// Register with encrypted data
router.post('/register', async (req, res) => {
  try {
    const { email, password, ssn, phone, creditCard } = req.body
    
    // Hash password (one-way)
    const passwordHash = await passwordService.hashPassword(password)
    
    // Create user with encrypted sensitive data
    const user = await prisma.user.create({
      data: {
        email,
        emailHash: encryptionService.hashForSearch(email),
        passwordHash,
        ssnEncrypted: ssn ? encryptionService.encrypt(ssn) : null,
        ssnHash: ssn ? encryptionService.hashForSearch(ssn) : null,
        phoneEncrypted: phone ? encryptionService.encrypt(phone) : null,
        phoneHash: phone ? encryptionService.hashForSearch(phone) : null,
        creditCard: creditCard ? encryptionService.encrypt(creditCard) : null
      }
    })
    
    res.json({ 
      id: user.id, 
      email: user.email,
      message: 'User created successfully' 
    })
  } catch (error) {
    res.status(400).json({ error: error.message })
  }
})

// Search by encrypted field
router.get('/search/ssn/:ssn', async (req, res) => {
  try {
    const ssnHash = encryptionService.hashForSearch(req.params.ssn)
    
    const user = await prisma.user.findFirst({
      where: { ssnHash },
      select: {
        id: true,
        email: true,
        ssnEncrypted: true
      }
    })
    
    if (user && user.ssnEncrypted) {
      // Decrypt for authorized user
      user.ssnEncrypted = encryptionService.decrypt(user.ssnEncrypted)
    }
    
    res.json(user)
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// Update password
router.put('/password', async (req, res) => {
  try {
    const { userId, oldPassword, newPassword } = req.body
    
    const user = await prisma.user.findUnique({
      where: { id: userId }
    })
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' })
    }
    
    // Verify old password
    const isValid = await passwordService.verifyPassword(
      oldPassword, 
      user.passwordHash
    )
    
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid password' })
    }
    
    // Hash new password
    const newPasswordHash = await passwordService.hashPassword(newPassword)
    
    await prisma.user.update({
      where: { id: userId },
      data: { 
        passwordHash: newPasswordHash,
        passwordChangedAt: new Date()
      }
    })
    
    res.json({ message: 'Password updated successfully' })
  } catch (error) {
    res.status(400).json({ error: error.message })
  }
})

export default router
```

### 9. Environment Configuration

```env
# .env
# Generate with: openssl rand -hex 32
ENCRYPTION_MASTER_KEY=your-256-bit-hex-key-here

# Bcrypt configuration
BCRYPT_ROUNDS=12

# Argon2 configuration (if using)
ARGON2_MEMORY_COST=65536
ARGON2_TIME_COST=3
ARGON2_PARALLELISM=1

# Security settings
PASSWORD_MIN_LENGTH=8
PASSWORD_MAX_LENGTH=128
PASSWORD_HISTORY_COUNT=5
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=1800000
```

---

## Security Best Practices

### Do's ✅

```typescript
// ✅ Hash passwords with bcrypt or Argon2
const hashedPassword = await bcrypt.hash(password, 12)

// ✅ Use constant-time comparison for passwords
const isValid = await bcrypt.compare(inputPassword, hashedPassword)

// ✅ Encrypt sensitive data that needs retrieval
const encryptedSSN = encryptionService.encrypt(ssn)

// ✅ Use environment variables for keys
const masterKey = process.env.ENCRYPTION_MASTER_KEY

// ✅ Implement rate limiting
const maxAttempts = 5

// ✅ Use HTTPS in production
app.use(forceSSL())

// ✅ Rotate encryption keys regularly
await keyRotationService.rotateKeys()

// ✅ Implement password policies
validatePasswordStrength(password)

// ✅ Hash searchable encrypted fields
const ssnHash = hmac(ssn, secretKey)
```

### Don'ts ❌

```typescript
// ❌ NEVER store plain passwords
user.password = plainPassword  // NEVER!

// ❌ NEVER decrypt passwords
const plainPassword = decrypt(encryptedPassword)  // IMPOSSIBLE with hash!

// ❌ Don't use weak hashing algorithms
const hash = md5(password)  // WEAK!
const hash = sha1(password)  // WEAK!

// ❌ Don't hardcode encryption keys
const key = "my-secret-key"  // BAD!

// ❌ Don't use the same salt for all passwords
const salt = "static-salt"  // BAD!

// ❌ Don't log sensitive data
console.log('Password:', password)  // NEVER!

// ❌ Don't transmit passwords in URLs
GET /api/login?password=secret  // BAD!

// ❌ Don't use reversible encoding for passwords
const encoded = base64.encode(password)  // NOT SECURE!
```

---

## Testing

```typescript
// tests/encryption.test.ts
describe('Encryption and Hashing', () => {
  describe('Password Hashing', () => {
    test('should hash and verify password', async () => {
      const password = 'Test@1234'
      const hash = await passwordService.hashPassword(password)
      
      expect(hash).not.toBe(password)
      expect(hash.length).toBeGreaterThan(50)
      
      const isValid = await passwordService.verifyPassword(password, hash)
      expect(isValid).toBe(true)
      
      const isInvalid = await passwordService.verifyPassword('wrong', hash)
      expect(isInvalid).toBe(false)
    })
    
    test('should generate different hashes for same password', async () => {
      const password = 'Test@1234'
      const hash1 = await passwordService.hashPassword(password)
      const hash2 = await passwordService.hashPassword(password)
      
      expect(hash1).not.toBe(hash2)
    })
  })
  
  describe('Data Encryption', () => {
    test('should encrypt and decrypt data', () => {
      const plaintext = 'Sensitive Data'
      const encrypted = encryptionService.encrypt(plaintext)
      
      expect(encrypted).not.toBe(plaintext)
      
      const decrypted = encryptionService.decrypt(encrypted)
      expect(decrypted).toBe(plaintext)
    })
    
    test('should generate unique encryption for same data', () => {
      const plaintext = 'Test Data'
      const encrypted1 = encryptionService.encrypt(plaintext)
      const encrypted2 = encryptionService.encrypt(plaintext)
      
      expect(encrypted1).not.toBe(encrypted2)
      
      // But both should decrypt to same value
      expect(encryptionService.decrypt(encrypted1)).toBe(plaintext)
      expect(encryptionService.decrypt(encrypted2)).toBe(plaintext)
    })
  })
})
```

---

## Quick Reference

### Password Hashing Libraries
- **bcrypt** - Most common, battle-tested
- **argon2** - Winner of Password Hashing Competition, more secure
- **scrypt** - Good alternative, memory-hard
- **pbkdf2** - Built into Node.js, acceptable

### Encryption Algorithms
- **AES-256-GCM** - Recommended, authenticated encryption
- **AES-256-CBC** - Older, requires separate MAC
- **ChaCha20-Poly1305** - Modern alternative to AES

### Key Sizes
- **AES-256**: 32 bytes (256 bits)
- **HMAC-SHA256**: 32 bytes minimum
- **bcrypt**: Automatically handled
- **Argon2**: Configurable memory/time

### Security Checklist
- ✅ Passwords hashed, never encrypted
- ✅ Minimum 12 rounds for bcrypt
- ✅ Encryption keys in environment variables
- ✅ HTTPS only in production
- ✅ Rate limiting on authentication
- ✅ Password complexity requirements
- ✅ Account lockout after failed attempts
- ✅ Regular key rotation
- ✅ Audit logging for sensitive operations
- ✅ No sensitive data in logs

Happy Secure Coding! 🔐
