# Database Relationships in Prisma: Beginner to Advanced

## 📚 Table of Contents

1. [Beginner: Core Relationships](#beginner-core-relationships)
2. [Intermediate: Complex Patterns](#intermediate-complex-patterns)
3. [Advanced: Production Patterns](#advanced-production-patterns)
4. [Performance & Best Practices](#performance--best-practices)
5. [Real-World Examples](#real-world-examples)

---

## Beginner: Core Relationships

### 1. One-to-One Relationships

**Use Cases**: User profile, settings, configuration

```prisma
model User {
  id       Int      @id @default(autoincrement())
  email    String   @unique
  name     String?
  profile  Profile? // Optional one-to-one
}

model Profile {
  id       Int    @id @default(autoincrement())
  bio      String
  avatar   String?
  userId   Int    @unique // Makes it one-to-one
  user     User   @relation(fields: [userId], references: [id])
}
```

**Operations**:
```typescript
// Create with relation
const user = await prisma.user.create({
  data: {
    email: 'john@example.com',
    profile: {
      create: { bio: 'Developer', avatar: 'avatar.jpg' }
    }
  },
  include: { profile: true }
})

// Read with relation
const userWithProfile = await prisma.user.findUnique({
  where: { email: 'john@example.com' },
  include: { profile: true }
})
```

---

### 2. One-to-Many Relationships

**Use Cases**: User posts, order items, comments

```prisma
model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  posts     Post[]   // One user, many posts
  comments  Comment[]
}

model Post {
  id        Int      @id @default(autoincrement())
  title     String
  content   String?
  authorId  Int      
  author    User     @relation(fields: [authorId], references: [id])
  comments  Comment[]
  
  @@index([authorId]) // Important for performance
}

model Comment {
  id        Int      @id @default(autoincrement())
  text      String
  authorId  Int
  postId    Int
  author    User     @relation(fields: [authorId], references: [id])
  post      Post     @relation(fields: [postId], references: [id])
  
  @@index([authorId, postId])
}
```

**Operations**:
```typescript
// Create with multiple relations
const user = await prisma.user.create({
  data: {
    email: 'blogger@example.com',
    posts: {
      create: [
        { title: 'First Post', content: 'Hello' },
        { title: 'Second Post', content: 'World' }
      ]
    }
  },
  include: { posts: true }
})

// Query with filters
const activePosts = await prisma.post.findMany({
  where: {
    authorId: userId,
    published: true
  },
  include: {
    comments: { take: 5 }
  }
})
```

---

### 3. Many-to-Many Relationships

**Implicit** (Prisma manages join table):
```prisma
model Post {
  id         Int        @id @default(autoincrement())
  title      String
  categories Category[] // Many-to-many
  tags       Tag[]
}

model Category {
  id    Int    @id @default(autoincrement())
  name  String @unique
  posts Post[]
}

model Tag {
  id    Int    @id @default(autoincrement())
  name  String @unique
  posts Post[]
}
```

**Explicit** (Custom join table with extra fields):
```prisma
model User {
  id         Int          @id @default(autoincrement())
  email      String       @unique
  followedBy Follows[]    @relation("following")
  following  Follows[]    @relation("follower")
}

model Follows {
  followerId  Int
  followingId Int
  createdAt   DateTime @default(now())
  follower    User     @relation("follower", fields: [followerId], references: [id])
  following   User     @relation("following", fields: [followingId], references: [id])
  
  @@id([followerId, followingId])
  @@index([followingId])
}
```

**Operations**:
```typescript
// Connect existing records
await prisma.post.update({
  where: { id: postId },
  data: {
    tags: {
      connect: [{ id: tagId1 }, { id: tagId2 }]
    }
  }
})

// Follow user (explicit)
await prisma.follows.create({
  data: {
    followerId: currentUserId,
    followingId: targetUserId
  }
})
```

---

## Intermediate: Complex Patterns

### 4. Self-Relations

**Use Cases**: Employee hierarchy, comment threads, folder structure

```prisma
// Hierarchical structure
model Employee {
  id           Int        @id @default(autoincrement())
  name         String
  managerId    Int?
  manager      Employee?  @relation("EmployeeManager", fields: [managerId], references: [id])
  subordinates Employee[] @relation("EmployeeManager")
  
  @@index([managerId])
}

// Tree structure
model Category {
  id       Int        @id @default(autoincrement())
  name     String
  parentId Int?
  parent   Category?  @relation("CategoryTree", fields: [parentId], references: [id])
  children Category[] @relation("CategoryTree")
}
```

**Recursive Queries**:
```typescript
// Get category path
async function getCategoryPath(categoryId: number): Promise<Category[]> {
  const category = await prisma.category.findUnique({
    where: { id: categoryId },
    include: { parent: true }
  })
  
  if (!category?.parent) return category ? [category] : []
  
  const parentPath = await getCategoryPath(category.parentId!)
  return [...parentPath, category]
}
```

---

### 5. Polymorphic Relations

**Pattern 1: Enum-based**:
```prisma
enum CommentableType {
  POST
  VIDEO
  ARTICLE
}

model Comment {
  id              Int              @id @default(autoincrement())
  text            String
  commentableId   Int
  commentableType CommentableType
  
  @@index([commentableType, commentableId])
}
```

**Pattern 2: JSON-based**:
```prisma
model Activity {
  id         Int      @id @default(autoincrement())
  userId     Int
  action     String   // "liked", "commented"
  targetType String   // "post", "video"
  targetId   Int
  metadata   Json?
  createdAt  DateTime @default(now())
  
  @@index([userId, createdAt])
  @@index([targetType, targetId])
}
```

---

### 6. Composite Relations

**Multi-tenant with composite keys**:
```prisma
model Organization {
  id       Int       @id @default(autoincrement())
  name     String
  projects Project[]
}

model Project {
  id    Int    @id @default(autoincrement())
  orgId Int
  name  String
  tasks Task[]
  org   Organization @relation(fields: [orgId], references: [id])
  
  @@unique([orgId, id])
}

model Task {
  id        Int     @id @default(autoincrement())
  orgId     Int
  projectId Int
  title     String
  project   Project @relation(fields: [orgId, projectId], references: [orgId, id])
  
  @@index([orgId, projectId])
}
```

---

## Advanced: Production Patterns

### 7. Soft Deletes

```prisma
model User {
  id        Int       @id @default(autoincrement())
  email     String    @unique
  deletedAt DateTime?
  posts     Post[]
  
  @@index([deletedAt])
}
```

```typescript
// Middleware for soft deletes
prisma.$use(async (params, next) => {
  if (params.action === 'delete') {
    params.action = 'update'
    params.args.data = { deletedAt: new Date() }
  }
  
  if (params.action === 'findMany') {
    params.args.where = {
      ...params.args.where,
      deletedAt: null
    }
  }
  
  return next(params)
})
```

---

### 8. Versioning

```prisma
model Document {
  id             Int               @id @default(autoincrement())
  title          String
  currentVersion Int               @default(1)
  versions       DocumentVersion[]
}

model DocumentVersion {
  id         Int      @id @default(autoincrement())
  documentId Int
  version    Int
  title      String
  content    String
  createdAt  DateTime @default(now())
  createdBy  Int
  
  @@unique([documentId, version])
  @@index([documentId, createdAt])
}
```

---

### 9. Graph Relations

```prisma
model User {
  id          Int          @id @default(autoincrement())
  username    String       @unique
  connections Connection[] @relation("UserConnections")
  connectedTo Connection[] @relation("ConnectedUsers")
}

model Connection {
  id            Int      @id @default(autoincrement())
  userId        Int
  connectedId   Int
  type          String   // "friend", "colleague"
  strength      Float    @default(1.0)
  user          User     @relation("UserConnections", fields: [userId], references: [id])
  connectedUser User     @relation("ConnectedUsers", fields: [connectedId], references: [id])
  
  @@unique([userId, connectedId])
}
```

```typescript
// Find mutual connections
async function getMutualConnections(userId1: number, userId2: number) {
  const [user1Conn, user2Conn] = await Promise.all([
    prisma.connection.findMany({
      where: { userId: userId1 },
      select: { connectedId: true }
    }),
    prisma.connection.findMany({
      where: { userId: userId2 },
      select: { connectedId: true }
    })
  ])
  
  const user1Set = new Set(user1Conn.map(c => c.connectedId))
  const user2Set = new Set(user2Conn.map(c => c.connectedId))
  
  const mutual = [...user1Set].filter(id => user2Set.has(id))
  
  return prisma.user.findMany({
    where: { id: { in: mutual } }
  })
}
```

---

## Performance & Best Practices

### Query Optimization

```typescript
// 1. Use select to minimize data
const posts = await prisma.post.findMany({
  select: {
    id: true,
    title: true,
    author: { select: { name: true } }
  }
})

// 2. Use aggregations for counts
const postsWithCount = await prisma.post.findMany({
  include: {
    _count: { select: { comments: true } }
  }
})

// 3. Batch operations
const users = await prisma.user.findMany({
  where: { id: { in: userIds } },
  include: { posts: true }
})

// 4. Pagination
const posts = await prisma.post.findMany({
  skip: 0,
  take: 20,
  cursor: { id: lastPostId },
  orderBy: { createdAt: 'desc' }
})
```

### Index Strategies

```prisma
model Post {
  id         Int      @id @default(autoincrement())
  title      String
  authorId   Int
  categoryId Int
  published  Boolean  @default(false)
  createdAt  DateTime @default(now())
  
  // Single indexes
  @@index([authorId])
  @@index([categoryId])
  @@index([createdAt(sort: Desc)])
  
  // Composite indexes for common queries
  @@index([authorId, published])
  @@index([categoryId, published, createdAt])
}
```

### Common Pitfalls

**N+1 Problem**:
```typescript
// ❌ BAD
const users = await prisma.user.findMany()
for (const user of users) {
  const posts = await prisma.post.findMany({
    where: { authorId: user.id }
  })
}

// ✅ GOOD
const users = await prisma.user.findMany({
  include: { posts: true }
})
```

**Over-fetching**:
```typescript
// ❌ BAD: Too much data
const users = await prisma.user.findMany({
  include: {
    posts: {
      include: {
        comments: {
          include: { author: true }
        }
      }
    }
  }
})

// ✅ GOOD: Only needed data
const users = await prisma.user.findMany({
  select: {
    id: true,
    name: true,
    _count: { select: { posts: true } }
  }
})
```

---

## Real-World Examples

### E-commerce Schema

```prisma
model Customer {
  id        Int       @id @default(autoincrement())
  email     String    @unique
  orders    Order[]
  addresses Address[]
  cart      Cart?
}

model Product {
  id         Int         @id @default(autoincrement())
  sku        String      @unique
  name       String
  price      Decimal
  stock      Int         @default(0)
  categoryId Int
  orderItems OrderItem[]
  reviews    Review[]
  
  @@index([categoryId])
  @@index([price])
}

model Order {
  id         Int         @id @default(autoincrement())
  customerId Int
  status     String      @default("pending")
  total      Decimal
  items      OrderItem[]
  
  @@index([customerId])
  @@index([status])
}

model OrderItem {
  orderId   Int
  productId Int
  quantity  Int
  price     Decimal
  order     Order   @relation(fields: [orderId], references: [id])
  product   Product @relation(fields: [productId], references: [id])
  
  @@id([orderId, productId])
}
```

### Social Media Schema

```prisma
model User {
  id          Int      @id @default(autoincrement())
  username    String   @unique
  posts       Post[]
  likes       Like[]
  followers   Follow[] @relation("UserFollowers")
  following   Follow[] @relation("UserFollowing")
}

model Post {
  id        Int       @id @default(autoincrement())
  content   String
  authorId  Int
  author    User      @relation(fields: [authorId], references: [id])
  likes     Like[]
  hashtags  Hashtag[]
  
  @@index([authorId])
}

model Follow {
  followerId  Int
  followingId Int
  createdAt   DateTime @default(now())
  follower    User     @relation("UserFollowing", fields: [followerId], references: [id])
  following   User     @relation("UserFollowers", fields: [followingId], references: [id])
  
  @@id([followerId, followingId])
}
```

### SaaS Multi-tenant

```prisma
model Tenant {
  id       String   @id @default(uuid())
  name     String
  plan     String
  users    User[]
  projects Project[]
}

model User {
  id       String  @id @default(uuid())
  tenantId String
  email    String
  tenant   Tenant  @relation(fields: [tenantId], references: [id])
  
  @@unique([tenantId, email])
  @@index([tenantId])
}

model Project {
  id       String @id @default(uuid())
  tenantId String
  name     String
  tenant   Tenant @relation(fields: [tenantId], references: [id])
  
  @@index([tenantId])
}
```

---

## Learning Path

### Beginner (Week 1-2)
- Master one-to-one, one-to-many, many-to-many
- Practice CRUD operations
- Understand foreign keys and indexes

### Intermediate (Week 3-4)
- Implement self-relations
- Work with polymorphic patterns
- Handle composite keys

### Advanced (Week 5-6)
- Implement soft deletes
- Build versioning systems
- Optimize queries

### Expert (Ongoing)
- Design complex schemas
- Performance tuning
- Scale to millions of records

---

## Quick Reference

```typescript
// Create with relations
prisma.model.create({
  data: {
    field: value,
    relation: {
      create: { /* data */ },    // Create new
      connect: { id: 1 },         // Connect existing
      connectOrCreate: { /* */ }  // Conditional
    }
  }
})

// Query with relations
prisma.model.findMany({
  where: { /* filters */ },
  include: {                     // Fetch full objects
    relation: true
  },
  select: {                       // Fetch specific fields
    field: true,
    relation: { select: { field: true } }
  }
})

// Update relations
prisma.model.update({
  where: { id: 1 },
  data: {
    relation: {
      set: [{ id: 1 }],          // Replace all
      connect: { id: 2 },        // Add one
      disconnect: { id: 3 },     // Remove one
      delete: true               // Delete related
    }
  }
})
```

Happy Learning! 🚀
