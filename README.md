# StyleDecor - Backend API Server

![StyleDecor](https://img.shields.io/badge/StyleDecor-Backend%20API-orange?style=for-the-badge)
![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=node.js)
![Express](https://img.shields.io/badge/Express-4.22.1-000000?style=for-the-badge&logo=express)
![MongoDB](https://img.shields.io/badge/MongoDB-6.21.0-47A248?style=for-the-badge&logo=mongodb)

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Live API](#live-api)
- [Tech Stack](#tech-stack)
- [NPM Packages](#npm-packages)
- [Features](#features)
- [API Endpoints](#api-endpoints)
- [Setup Instructions](#setup-instructions)
- [Environment Variables](#environment-variables)
- [Database Schema](#database-schema)
- [Authentication](#authentication)
- [Payment Integration](#payment-integration)
- [Deployment](#deployment)
- [Repository Links](#repository-links)

## 🎯 Project Overview

**StyleDecor Backend** is a robust RESTful API server built with Express.js and MongoDB, designed to power the StyleDecor decoration booking platform. It provides comprehensive endpoints for user authentication, service management, booking operations, payment processing, and analytics.

The API is optimized for serverless deployment on Vercel with connection pooling, lazy initialization, and parallel query execution for optimal performance.

## 🌐 Live API

**API Base URL:** [https://style-decor-server-sami.vercel.app](https://style-decor-server-sami.vercel.app)

**Status Endpoint:** `GET /` - Returns API health status and timestamp

## 🛠 Tech Stack

### Core Technologies
- **Node.js 18+** - JavaScript runtime
- **Express.js 4.22.1** - Web application framework
- **MongoDB 6.21.0** - NoSQL database with native driver
- **Firebase Admin 12.7.0** - Authentication and user management
- **JWT (jsonwebtoken 9.0.3)** - Token-based authentication
- **Stripe 14.25.0** - Payment processing

### Security & Utilities
- **bcryptjs 2.4.3** - Password hashing
- **CORS 2.8.5** - Cross-origin resource sharing
- **dotenv 16.6.1** - Environment variable management
- **Axios 1.13.2** - HTTP client for external APIs

## 📦 NPM Packages

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `express` | ^4.22.1 | Web server framework |
| `mongodb` | ^6.21.0 | MongoDB native driver |
| `firebase-admin` | ^12.7.0 | Firebase authentication |
| `jsonwebtoken` | ^9.0.3 | JWT token generation/verification |
| `bcryptjs` | ^2.4.3 | Password hashing |
| `stripe` | ^14.25.0 | Payment processing |
| `cors` | ^2.8.5 | CORS middleware |
| `dotenv` | ^16.6.1 | Environment variables |
| `axios` | ^1.13.2 | HTTP client |

### Dev Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `nodemon` | ^3.0.3 | Development auto-reload |

## ✨ Features

### 🔐 Authentication & Authorization
- **Dual Authentication**: JWT and Firebase token verification
- **Role-Based Access Control**: User, Decorator, and Admin roles
- **Social Login Support**: Google OAuth via Firebase
- **Secure Password Hashing**: bcrypt with salt rounds
- **Token Expiration**: 7-day JWT tokens

### 🎨 Service Management
- **CRUD Operations**: Full service lifecycle management
- **Advanced Filtering**: Search by name, category, price range
- **Pagination Support**: Efficient data loading
- **Image Upload**: ImgBB integration for service images

### 📅 Booking System
- **User Bookings**: Create, view, and cancel bookings
- **Decorator Assignment**: Admin assigns decorators to bookings
- **Status Tracking**: 9-stage booking workflow
- **Project Management**: Decorator dashboard for assigned projects

### 💳 Payment Processing
- **Stripe Integration**: Secure payment processing
- **Checkout Sessions**: Hosted Stripe Checkout
- **Payment Verification**: Server-side payment confirmation
- **Payment History**: Complete transaction records
- **Currency Conversion**: BDT to USD conversion (1 USD = 110 BDT)

### 👥 User Management
- **User Profiles**: Display name, email, profile image
- **Decorator Promotion**: Admin can promote users to decorators
- **Role Toggle**: Switch between user and decorator roles
- **Account Status**: Enable/disable decorator accounts

### 📊 Analytics & Reporting
- **Platform Statistics**: Users, decorators, services, bookings
- **Revenue Tracking**: Total revenue and payment analytics
- **Service Demand**: Top 10 most booked services
- **Decorator Earnings**: 40% commission on completed projects

### ⚡ Performance Optimizations
- **Connection Pooling**: MongoDB connection caching
- **Lazy Initialization**: Firebase Admin loaded on-demand
- **Parallel Queries**: Concurrent database operations
- **Database Projections**: Fetch only required fields
- **Non-blocking Initialization**: Background index creation

## 🔗 API Endpoints

### Authentication Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/auth/register` | None | Register new user |
| `POST` | `/api/auth/login` | None | Login with email/password or Firebase token |
| `GET` | `/api/auth/me` | Required | Get current user profile |

### Service Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/services` | None | Get all services (with filters) |
| `GET` | `/api/services/:id` | None | Get service by ID |
| `POST` | `/api/services` | Admin | Create new service |
| `PUT` | `/api/services/:id` | Admin | Update service |
| `DELETE` | `/api/services/:id` | Admin | Delete service |

### Booking Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/bookings` | User | Create new booking |
| `GET` | `/api/bookings/my-bookings` | User | Get user's bookings |
| `GET` | `/api/bookings` | Admin | Get all bookings |
| `PATCH` | `/api/bookings/:id/status` | Admin/Decorator | Update booking status |
| `PATCH` | `/api/bookings/:id/assign-decorator` | Admin | Assign decorator to booking |
| `PATCH` | `/api/bookings/:id/cancel` | User | Cancel booking |
| `GET` | `/api/bookings/my-assignments` | Decorator | Get decorator's assigned projects |

### Payment Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/payments/create-checkout-session` | User | Create Stripe checkout session |
| `POST` | `/api/payments/verify-session` | User | Verify payment after checkout |
| `POST` | `/api/payments/create-intent` | User | Create payment intent (legacy) |
| `POST` | `/api/payments/confirm` | User | Confirm payment |
| `GET` | `/api/payments/my-payments` | User | Get user's payment history |
| `GET` | `/api/payments` | Admin | Get all payments |

### User Management Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/users` | Admin | Get all users (with filters) |
| `PATCH` | `/api/users/:email/make-decorator` | Admin | Promote user to decorator |
| `PATCH` | `/api/users/:email/toggle-role` | Admin | Toggle user/decorator role |

### Decorator Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/decorators` | None | Get all decorators |
| `GET` | `/api/decorators/earnings` | Decorator | Get decorator earnings |
| `PATCH` | `/api/decorators/:email/toggle-status` | Admin | Enable/disable decorator |

### Analytics Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/analytics/stats` | Admin | Get platform statistics |
| `GET` | `/api/analytics/service-demand` | Admin | Get service demand data |

### Utility Routes

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/upload-image` | None | Upload image to ImgBB |
| `GET` | `/` | None | API health check |

## 🚀 Setup Instructions

### Prerequisites

- **Node.js** 18+ and npm
- **MongoDB Atlas** account (or local MongoDB instance)
- **Firebase** project with Admin SDK credentials
- **Stripe** account with API keys
- **ImgBB** API key for image uploads

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/XDR-SAM/StyleDecor-Server.git
cd StyleDecor-Server
```

2. **Install dependencies**

```bash
npm install
```

3. **Set up environment variables** (see [Environment Variables](#environment-variables))

4. **Start the development server**

```bash
npm run dev
```

The API will be available at `http://localhost:5000`

5. **Start the production server**

```bash
npm start
```

## 🔐 Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Server Configuration
PORT=5000
NODE_ENV=development

# Frontend URL
FRONTEND_URL=http://localhost:5173

# MongoDB Configuration
MONGODB_URI=your_mongodb_connection_string
DB_NAME=styledecor

# Super Admin Credentials
SUPER_ADMIN_EMAIL=admin@styledecor.com
SUPER_ADMIN_PASSWORD=your_secure_password

# JWT Configuration
JWT_SECRET=your_jwt_secret_key

# Firebase Admin SDK
FIREBASE_PROJECT_ID=your_firebase_project_id
FIREBASE_PRIVATE_KEY=your_firebase_private_key
FIREBASE_CLIENT_EMAIL=your_firebase_client_email

# Stripe Configuration
STRIPE_SECRET_KEY=your_stripe_secret_key

# ImgBB Configuration
IMGBB_API_KEY=your_imgbb_api_key
```

### Environment Variable Details

- **MONGODB_URI**: MongoDB Atlas connection string or local MongoDB URL
- **JWT_SECRET**: Secret key for signing JWT tokens (use a strong random string)
- **FIREBASE_PRIVATE_KEY**: Firebase Admin SDK private key (replace `\n` with actual newlines)
- **STRIPE_SECRET_KEY**: Stripe secret key from your Stripe dashboard
- **IMGBB_API_KEY**: API key from ImgBB for image hosting
- **SUPER_ADMIN_EMAIL/PASSWORD**: Initial admin account credentials

## 📊 Database Schema

### Collections

#### `users`
```javascript
{
  _id: ObjectId,
  email: String (unique, indexed),
  password: String (hashed),
  displayName: String,
  profileImage: String,
  role: String, // 'user', 'decorator', 'admin'
  authProvider: String, // 'google', undefined
  isActive: Boolean,
  // Decorator-specific fields
  specialty: String,
  rating: Number,
  experience: String,
  createdAt: Date,
  updatedAt: Date
}
```

#### `services`
```javascript
{
  _id: ObjectId,
  service_name: String (indexed),
  cost: Number,
  unit: String,
  service_category: String,
  description: String,
  imageUrl: String,
  createdByEmail: String,
  isActive: Boolean,
  createdAt: Date,
  updatedAt: Date
}
```

#### `bookings`
```javascript
{
  _id: ObjectId,
  serviceId: ObjectId,
  serviceName: String,
  serviceCost: Number,
  userEmail: String (indexed),
  userName: String,
  bookingDate: Date,
  location: String,
  userNotes: String,
  status: String, // 'pending', 'confirmed', 'assigned', 'planning', 
                  // 'materials-prepared', 'on-the-way', 'in-progress',
                  // 'completed', 'cancelled'
  isPaid: Boolean,
  paymentStatus: String, // 'unpaid', 'paid'
  assignedDecorator: String, // email
  createdAt: Date,
  updatedAt: Date,
  paidAt: Date,
  cancelledAt: Date
}
```

#### `payments`
```javascript
{
  _id: ObjectId,
  bookingId: ObjectId,
  userEmail: String,
  amount: Number, // in BDT
  amountUSD: String,
  paymentIntentId: String,
  sessionId: String,
  currency: String,
  status: String, // 'completed'
  createdAt: Date
}
```

## 🔒 Authentication

### JWT Authentication

The API uses JWT tokens for authentication. After login/registration, clients receive a JWT token that must be included in subsequent requests:

```
Authorization: Bearer <token>
```

**Token Payload:**
```javascript
{
  email: String,
  userId: ObjectId,
  role: String,
  exp: Number // 7 days from issue
}
```

### Firebase Authentication

The API also supports Firebase ID tokens for Google OAuth users. The server verifies Firebase tokens and creates/updates local user records.

### Middleware

- **`verifyToken`**: Validates JWT or Firebase token
- **`verifyAdmin`**: Ensures user has admin role
- **`verifyDecorator`**: Ensures user has decorator or admin role

## 💳 Payment Integration

### Stripe Checkout Flow

1. **Create Checkout Session**: Client calls `/api/payments/create-checkout-session`
2. **Redirect to Stripe**: Client redirects to Stripe Checkout URL
3. **Payment Processing**: User completes payment on Stripe
4. **Return to App**: Stripe redirects to success/cancel URL
5. **Verify Payment**: Client calls `/api/payments/verify-session`
6. **Update Booking**: Server marks booking as paid and confirmed

### Currency Conversion

- **Exchange Rate**: 1 USD = 110 BDT (hardcoded)
- **Stripe Currency**: USD (Stripe requirement)
- **Display Currency**: BDT (for users)

### Decorator Commission

- **Commission Rate**: 40% of project cost
- **Calculation**: Triggered when booking status = 'completed' and isPaid = true
- **Endpoint**: `/api/decorators/earnings`

## 📁 Project Structure

```
StyleDecor-Server/
├── .git/                    # Git repository
├── .gitignore              # Git ignore rules
├── index.js                # Main application file (1488 lines)
├── package.json            # NPM dependencies
├── vercel.json             # Vercel deployment config
└── README.md               # This file
```

### Code Organization (index.js)

- **Lines 1-90**: Dependencies, middleware, Firebase/MongoDB setup
- **Lines 91-151**: Database initialization and indexing
- **Lines 153-220**: JWT middleware (verifyToken, verifyAdmin, verifyDecorator)
- **Lines 222-229**: Health check route
- **Lines 231-399**: Authentication routes (register, login, me)
- **Lines 401-428**: Image upload route
- **Lines 431-578**: Service CRUD routes
- **Lines 580-834**: Booking routes
- **Lines 836-883**: Decorator earnings route
- **Lines 885-1179**: Payment routes (Stripe integration)
- **Lines 1181-1229**: User management routes
- **Lines 1231-1385**: Decorator management routes
- **Lines 1387-1454**: Analytics routes
- **Lines 1456-1488**: Error handling and server start

## 🚀 Deployment

### Vercel Deployment

The API is optimized for Vercel serverless deployment:

1. **Install Vercel CLI**
```bash
npm install -g vercel
```

2. **Login to Vercel**
```bash
vercel login
```

3. **Deploy**
```bash
vercel --prod
```

4. **Configure Environment Variables**
   - Go to Vercel Dashboard → Project Settings → Environment Variables
   - Add all variables from `.env` file

### Vercel Configuration (`vercel.json`)

```json
{
  "version": 2,
  "builds": [
    {
      "src": "index.js",
      "use": "@vercel/node"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "index.js"
    }
  ],
  "env": {
    "NODE_ENV": "production"
  }
}
```

### Performance Optimizations for Vercel

- **Connection Caching**: MongoDB connections cached across invocations
- **Lazy Initialization**: Firebase Admin loaded only when needed
- **Non-blocking Setup**: Database indexes created in background
- **Parallel Queries**: Multiple database operations run concurrently
- **Projection Optimization**: Fetch only required fields

## 📜 Available Scripts

| Script | Description |
|--------|-------------|
| `npm start` | Start production server |
| `npm run dev` | Start development server with nodemon |

## 🔗 Repository Links

- **Frontend Repository**: [https://github.com/XDR-SAM/StyleDecor-Cleint.git](https://github.com/XDR-SAM/StyleDecor-Cleint.git)
- **Backend Repository**: [https://github.com/XDR-SAM/StyleDecor-Server.git](https://github.com/XDR-SAM/StyleDecor-Server.git)
- **Live Application**: [https://style-decor-sami.vercel.app/](https://style-decor-sami.vercel.app/)
- **Live API**: [https://style-decor-server-ochre.vercel.app](https://style-decor-server-ochre.vercel.app)

## 🔒 Security Features

- **Password Hashing**: bcrypt with 10 salt rounds
- **JWT Tokens**: 7-day expiration with secure secret
- **Firebase Verification**: Server-side token validation
- **Role-Based Access**: Middleware-enforced permissions
- **CORS Protection**: Configured allowed origins
- **Input Validation**: Request body validation
- **SQL Injection Prevention**: MongoDB native driver with ObjectId
- **XSS Protection**: Express built-in protections

## 🎯 Booking Status Workflow

The booking system supports a 9-stage workflow:

1. **pending** - Initial booking created
2. **confirmed** - Payment completed
3. **assigned** - Decorator assigned by admin
4. **planning** - Decorator planning the project
5. **materials-prepared** - Materials ready
6. **on-the-way** - Decorator traveling to location
7. **in-progress** - Active decoration work
8. **completed** - Project finished
9. **cancelled** - Booking cancelled

## 📊 API Response Format

### Success Response
```json
{
  "message": "Operation successful",
  "data": { ... },
  "pagination": {
    "total": 100,
    "page": 1,
    "limit": 10,
    "totalPages": 10
  }
}
```

### Error Response
```json
{
  "message": "Error description",
  "error": "Detailed error message (development only)"
}
```

## 📝 License

This project is part of Assignment 11 from Programming Hero (PH).

## 👨‍💻 Author

**XDR-SAM**

- GitHub: [@XDR-SAM](https://github.com/XDR-SAM)
- Live Demo: [StyleDecor](https://style-decor-sami.vercel.app/)
- API: [StyleDecor API](https://style-decor-server-ochre.vercel.app)

## 🙏 Acknowledgments

- Programming Hero for the assignment 
- MongoDB for the robust database solution
- Firebase for authentication services
- Stripe for payment processing infrastructure
- Vercel for serverless deployment platform
- ImgBB for image hosting services

---

**⭐ If you find this project helpful, please consider giving it a star!**
