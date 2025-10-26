# Learn Prisma: Complete Step-by-Step Guide

## 📚 Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Step 1: Environment Setup](#step-1-environment-setup)
4. [Step 2: Initialize Prisma](#step-2-initialize-prisma)
5. [Step 3: Understanding Prisma Schema](#step-3-understanding-prisma-schema)
6. [Step 4: Basic CRUD Operations](#step-4-basic-crud-operations)
7. [Step 5: Relations and Advanced Queries](#step-5-relations-and-advanced-queries)
8. [Step 6: Migrations](#step-6-migrations)
9. [Step 7: Advanced Features](#step-7-advanced-features)
10. [Step 8: Best Practices](#step-8-best-practices)
11. [Practice Projects](#practice-projects)
12. [Resources](#resources)

---

## Introduction

**Prisma** is a next-generation Node.js and TypeScript ORM that helps developers build faster and make fewer errors. It consists of:

- **Prisma Client**: Auto-generated and type-safe query builder
- **Prisma Migrate**: Declarative data modeling & migration system
- **Prisma Studio**: GUI to view and edit data in your database

---

## Prerequisites

Before starting, ensure you have:

- **Node.js** (v14.17.0 or higher)
- **npm** or **yarn** package manager
- **PostgreSQL** database (already set up with Docker ✅)
- Basic knowledge of JavaScript/TypeScript
- Basic understanding of databases and SQL

---

## Step 1: Environment Setup

### 1.1 Start Your Database

```bash
# Start PostgreSQL with Docker
docker-compose up -d

# Verify it's running
docker ps
```

### 1.2 Initialize Node.js Project

```bash
# Create a new directory for your Prisma project
mkdir prisma-learning
cd prisma-learning

# Initialize npm project
npm init -y

# Install TypeScript and development dependencies
npm install -D typescript ts-node @types/node nodemon
```

### 1.3 Configure TypeScript

```bash
# Create tsconfig.json
npx tsc --init
```

---

## Step 2: Initialize Prisma

### 2.1 Install Prisma

```bash
# Install Prisma CLI as dev dependency
npm install -D prisma

# Install Prisma Client
npm install @prisma/client
```

### 2.2 Initialize Prisma with PostgreSQL

```bash
# Initialize Prisma with PostgreSQL provider
npx prisma init --datasource-provider postgresql
```

This creates:

- `prisma/schema.prisma` - Your database schema
- `.env` - Environment variables for database connection

### 2.3 Configure Database Connection

Update your `.env` file:

```env
DATABASE_URL="postgresql://admin:admin123@localhost:5432/mydb?schema=public"
```

---

## Step 3: Understanding Prisma Schema

### 3.1 Basic Model Definition

```prisma
// prisma/schema.prisma

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

// Define your first model
model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  name      String?
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

### 3.2 Data Types

- **Scalar types**: String, Int, Float, Boolean, DateTime, Json
- **Modifiers**: `?` for optional, `[]` for arrays
- **Attributes**: `@id`, `@unique`, `@default()`, `@updatedAt`

### 3.3 Create Your First Migration

```bash
# Create and apply migration
npx prisma migrate dev --name init

# Generate Prisma Client
npx prisma generate
```

---

## Step 4: Basic CRUD Operations

### 4.1 Create a Script File

```typescript
// src/index.ts
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  // Your code here
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
```

### 4.2 CREATE Operations

```typescript
// Create single user
const user = await prisma.user.create({
  data: {
    email: "alice@example.com",
    name: "Alice",
  },
});

// Create multiple users
const users = await prisma.user.createMany({
  data: [
    { email: "bob@example.com", name: "Bob" },
    { email: "charlie@example.com", name: "Charlie" },
  ],
});
```

### 4.3 READ Operations

```typescript
// Find all users
const allUsers = await prisma.user.findMany();

// Find unique user
const user = await prisma.user.findUnique({
  where: { email: "alice@example.com" },
});

// Find first matching user
const firstUser = await prisma.user.findFirst({
  where: {
    name: { contains: "Ali" },
  },
});
```

### 4.4 UPDATE Operations

```typescript
// Update single user
const updatedUser = await prisma.user.update({
  where: { email: "alice@example.com" },
  data: { name: "Alice Smith" },
});

// Update multiple users
const updateMany = await prisma.user.updateMany({
  where: { name: { contains: "Bob" } },
  data: { name: "Robert" },
});
```

### 4.5 DELETE Operations

```typescript
// Delete single user
const deletedUser = await prisma.user.delete({
  where: { email: "charlie@example.com" },
});

// Delete multiple users
const deleteMany = await prisma.user.deleteMany({
  where: { email: { contains: "test" } },
});
```

---

## Step 5: Relations and Advanced Queries

### 5.1 Define Relations in Schema

```prisma
model User {
  id       Int      @id @default(autoincrement())
  email    String   @unique
  name     String?
  posts    Post[]   // One-to-many relation
  profile  Profile? // One-to-one relation
}

model Post {
  id        Int      @id @default(autoincrement())
  title     String
  content   String?
  published Boolean  @default(false)
  authorId  Int
  author    User     @relation(fields: [authorId], references: [id])
  tags      Tag[]    // Many-to-many relation
}

model Profile {
  id     Int    @id @default(autoincrement())
  bio    String
  userId Int    @unique
  user   User   @relation(fields: [userId], references: [id])
}

model Tag {
  id    Int    @id @default(autoincrement())
  name  String @unique
  posts Post[] // Many-to-many relation
}
```

### 5.2 Nested Writes

```typescript
// Create user with posts
const userWithPosts = await prisma.user.create({
  data: {
    email: "alice@example.com",
    name: "Alice",
    posts: {
      create: [
        { title: "First Post", content: "Hello World" },
        { title: "Second Post", content: "Prisma is awesome" },
      ],
    },
  },
});
```

### 5.3 Include Relations

```typescript
// Fetch user with posts
const userWithPosts = await prisma.user.findUnique({
  where: { email: "alice@example.com" },
  include: {
    posts: true,
    profile: true,
  },
});

// Nested includes
const posts = await prisma.post.findMany({
  include: {
    author: {
      include: {
        profile: true,
      },
    },
    tags: true,
  },
});
```

### 5.4 Filtering and Sorting

```typescript
// Complex filtering
const filteredPosts = await prisma.post.findMany({
  where: {
    OR: [
      { title: { contains: "Prisma" } },
      { content: { contains: "database" } },
    ],
    AND: {
      published: true,
      author: {
        email: { endsWith: "@example.com" },
      },
    },
  },
  orderBy: {
    createdAt: "desc",
  },
  skip: 0,
  take: 10,
});
```

---

## Step 6: Migrations

### 6.1 Development Workflow

```bash
# Create a migration after schema changes
npx prisma migrate dev --name add_user_role

# Reset database (WARNING: Deletes all data)
npx prisma migrate reset

# Check migration status
npx prisma migrate status
```

### 6.2 Production Migrations

```bash
# Deploy migrations to production
npx prisma migrate deploy

# Generate migration SQL without applying
npx prisma migrate dev --create-only
```

### 6.3 Seeding Database

Create `prisma/seed.ts`:

```typescript
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function seed() {
  // Create seed data
  await prisma.user.createMany({
    data: [
      { email: "admin@example.com", name: "Admin" },
      { email: "user@example.com", name: "User" },
    ],
  });
}

seed()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
```

Add to `package.json`:

```json
{
  "prisma": {
    "seed": "ts-node prisma/seed.ts"
  }
}
```

Run seed:

```bash
npx prisma db seed
```

---

## Step 7: Advanced Features

### 7.1 Transactions

```typescript
// Interactive transactions
const result = await prisma.$transaction(async (tx) => {
  const user = await tx.user.create({
    data: { email: "new@example.com", name: "New User" },
  });

  const profile = await tx.profile.create({
    data: {
      bio: "Hello!",
      userId: user.id,
    },
  });

  return { user, profile };
});

// Sequential transactions
const [users, posts] = await prisma.$transaction([
  prisma.user.findMany(),
  prisma.post.findMany(),
]);
```

### 7.2 Raw Queries

```typescript
// Raw SQL queries


// Execute raw SQL
const deleted = await prisma.$executeRaw`
  DELETE FROM "Post" 
  WHERE "createdAt" < ${oneYearAgo}
`;
```

### 7.3 Aggregations

```typescript
// Count, avg, sum, min, max
const aggregations = await prisma.user.aggregate({
  _count: { id: true },
  _avg: { age: true },
  _sum: { points: true },
  _min: { createdAt: true },
  _max: { createdAt: true },
});

// Group by
const grouped = await prisma.post.groupBy({
  by: ["published"],
  _count: { id: true },
});
```

### 7.4 Middleware

```typescript
// Log all queries
prisma.$use(async (params, next) => {
  const before = Date.now();
  const result = await next(params);
  const after = Date.now();

  console.log(
    `Query ${params.model}.${params.action} took ${after - before}ms`
  );

  return result;
});
```

---

## Step 8: Best Practices

### 8.1 Type Safety

```typescript
// Use generated types
import { User, Prisma } from "@prisma/client";

// Type-safe where conditions
const whereCondition: Prisma.UserWhereInput = {
  email: { contains: "@example.com" },
  createdAt: { gte: new Date("2024-01-01") },
};

// Type-safe select
const userSelect: Prisma.UserSelect = {
  id: true,
  email: true,
  posts: {
    select: {
      title: true,
    },
  },
};
```

### 8.2 Error Handling

```typescript
import { Prisma } from "@prisma/client";

try {
  await prisma.user.create({
    data: { email: "duplicate@example.com" },
  });
} catch (error) {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === "P2002") {
      console.log("Unique constraint violation");
    }
  }
  throw error;
}
```

### 8.3 Connection Management

```typescript
// Singleton pattern for Prisma Client
class PrismaService {
  private static instance: PrismaClient;

  static getInstance(): PrismaClient {
    if (!PrismaService.instance) {
      PrismaService.instance = new PrismaClient({
        log: ["query", "info", "warn", "error"],
      });
    }
    return PrismaService.instance;
  }
}
```

### 8.4 Performance Optimization

```typescript
// Use select to fetch only needed fields
const users = await prisma.user.findMany({
  select: {
    id: true,
    email: true,
  },
});

// Use findFirst instead of findMany + [0]
const firstUser = await prisma.user.findFirst();

// Batch operations
const batchUpdate = await prisma.user.updateMany({
  where: { role: "USER" },
  data: { verified: true },
});
```

---

## Practice Projects

### Beginner Level

1. **Todo App**: Create a simple todo list with CRUD operations
2. **User Authentication**: Build login/register with hashed passwords
3. **Blog Platform**: Create posts with categories and comments

### Intermediate Level

1. **E-commerce API**: Products, categories, orders, and cart
2. **Social Media Backend**: Users, posts, likes, comments, followers
3. **Task Management**: Projects, tasks, teams, and assignments

### Advanced Level

1. **Multi-tenant SaaS**: Organizations, roles, permissions
2. **Real-time Chat**: Messages, rooms, online status
3. **Analytics Dashboard**: Data aggregation and reporting

---

## Resources

### Official Documentation

- **[Prisma Docs](https://www.prisma.io/docs)** - Complete documentation
- **[Prisma Examples](https://github.com/prisma/prisma-examples)** - Sample projects
- **[Prisma Playground](https://playground.prisma.io)** - Interactive learning

### Tutorials & Courses

- **[Prisma&#39;s Data Guide](https://www.prisma.io/dataguide)** - Database fundamentals
- **[Prisma YouTube Channel](https://www.youtube.com/c/PrismaData)** - Video tutorials
- **[Prisma Blog](https://www.prisma.io/blog)** - Articles and updates

### Tools

- **[Prisma Studio](https://www.prisma.io/studio)** - GUI for database
- **[Prisma Migrate](https://www.prisma.io/migrate)** - Migration tool
- **[Prisma Client](https://www.prisma.io/client)** - Type-safe database client

### Community

- **[Prisma Slack](https://slack.prisma.io)** - Community chat
- **[GitHub Discussions](https://github.com/prisma/prisma/discussions)** - Q&A forum
- **[Stack Overflow](https://stackoverflow.com/questions/tagged/prisma)** - Questions & answers

---

## Next Steps

1. ✅ Complete the basic setup and CRUD operations
2. ✅ Practice with relations and advanced queries
3. ✅ Build a small project using Prisma
4. ✅ Explore Prisma's ecosystem (Nexus, GraphQL, tRPC)
5. ✅ Contribute to open-source Prisma projects

---

## Quick Commands Reference

```bash
# Initialize Prisma
npx prisma init

# Generate Prisma Client
npx prisma generate

# Create migration
npx prisma migrate dev --name <name>

# Deploy migrations
npx prisma migrate deploy

# Reset database
npx prisma migrate reset

# Open Prisma Studio
npx prisma studio

# Format schema
npx prisma format

# Validate schema
npx prisma validate

# Database push (skip migrations)
npx prisma db push

# Database pull (introspect)
npx prisma db pull

# Seed database
npx prisma db seed
```

---

💡 **Pro Tip**: Start with a simple project and gradually add complexity. Prisma's type safety will help you avoid errors and build faster!

Happy Learning! 🚀
