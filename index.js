const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ============ Middleware ============
app.use(cors({
  origin: [process.env.FRONTEND_URL, 'http://localhost:5173', 'http://localhost:5174' , 'https://magical-dusk-71097f.netlify.app'],
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ============ Firebase Admin Initialization ============
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
};

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('✅ Firebase Admin initialized successfully');
} catch (error) {
  console.error('❌ Firebase Admin initialization failed:', error.message);
}

// ============ MongoDB Connection ============
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let db;
let usersCollection;
let servicesCollection;
let bookingsCollection;
let paymentsCollection;

async function connectDB() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("✅ Successfully connected to MongoDB!");

    db = client.db(process.env.DB_NAME || 'styledecor');
    usersCollection = db.collection('users');
    servicesCollection = db.collection('services');
    bookingsCollection = db.collection('bookings');
    paymentsCollection = db.collection('payments');

    await usersCollection.createIndex({ email: 1 }, { unique: true });
    await servicesCollection.createIndex({ service_name: 1 });
    await bookingsCollection.createIndex({ userEmail: 1 });

    await initializeSuperAdmin();
  } catch (error) {
    console.error("❌ MongoDB connection failed:", error);
    process.exit(1);
  }
}

connectDB();

// ============ Initialize Super Admin ============
async function initializeSuperAdmin() {
  try {
    const existingAdmin = await usersCollection.findOne({ 
      email: process.env.SUPER_ADMIN_EMAIL 
    });

    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(process.env.SUPER_ADMIN_PASSWORD, 10);
      await usersCollection.insertOne({
        email: process.env.SUPER_ADMIN_EMAIL,
        password: hashedPassword,
        displayName: 'Super Admin',
        role: 'admin',
        profileImage: '',
        createdAt: new Date(),
        isActive: true
      });
      console.log('✅ Super Admin created successfully');
    } else {
      console.log('ℹ️  Super Admin already exists');
    }
  } catch (error) {
    console.error('❌ Super Admin initialization failed:', error);
  }
}
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    try {
      const decodedToken = await admin.auth().verifyIdToken(token);
      req.user = decodedToken;
      next();
    } catch (firebaseError) {
      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
          return res.status(403).json({ message: 'Invalid token' });
        }
        req.user = decoded;
        next();
      });
    }
  } catch (error) {
    res.status(403).json({ message: 'Token verification failed' });
  }
};

const verifyAdmin = async (req, res, next) => {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (user?.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Authorization check failed' });
  }
};

const verifyDecorator = async (req, res, next) => {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (user?.role !== 'decorator' && user?.role !== 'admin') {
      return res.status(403).json({ message: 'Decorator access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Authorization check failed' });
  }
};
app.get('/', (req, res) => {
  res.json({ 
    message: 'StyleDecor API is running',
    status: 'active',
    timestamp: new Date()
  });
});
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, displayName, profileImage } = req.body;

    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      email,
      password: hashedPassword,
      displayName,
      profileImage: profileImage || '',
      role: 'user',
      createdAt: new Date(),
      isActive: true
    };

    const result = await usersCollection.insertOne(newUser);

    const token = jwt.sign(
      { email, userId: result.insertedId, role: 'user' },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        email,
        displayName,
        role: 'user',
        profileImage: profileImage || ''
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Registration failed', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(403).json({ message: 'Account is disabled' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { email: user.email, userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        email: user.email,
        displayName: user.displayName,
        role: user.role,
        profileImage: user.profileImage
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed', error: error.message });
  }
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const user = await usersCollection.findOne(
      { email: req.user.email },
      { projection: { password: 0 } }
    );
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Failed to get user data' });
  }
});
app.post('/api/upload-image', async (req, res) => {
  try {
    const { image } = req.body;

    if (!image) {
      return res.status(400).json({ message: 'No image provided' });
    }

    const formData = new URLSearchParams();
    formData.append('key', process.env.IMGBB_API_KEY);
    formData.append('image', image.split(',')[1] || image);

    const response = await axios.post('https://api.imgbb.com/1/upload', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    res.json({
      success: true,
      url: response.data.data.url,
      deleteUrl: response.data.data.delete_url
    });
  } catch (error) {
    console.error('Image upload error:', error.response?.data || error.message);
    res.status(500).json({ message: 'Image upload failed' });
  }
});
