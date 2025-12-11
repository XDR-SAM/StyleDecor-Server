/* eslint-env node */
/* eslint-disable */
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// ============ Middleware ============
app.use(cors({
  origin: [process.env.FRONTEND_URL, 'http://localhost:5173', 'http://localhost:5174', 'https://magical-dusk-71097f.netlify.app'],
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ============ Firebase Admin Lazy Initialization ============
// OPTIMIZATION: Lazy load Firebase only when needed
let adminInitialized = false;
let admin = null;

function getFirebaseAdmin() {
  if (!adminInitialized) {
    admin = require('firebase-admin');
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
      adminInitialized = true;
    } catch (error) {
      console.error('❌ Firebase Admin initialization failed:', error.message);
    }
  }
  return admin;
}

// ============ MongoDB Connection with Caching ============
// OPTIMIZATION: Cache connection across serverless invocations
let cachedClient = null;
let cachedDb = null;

const mongoClient = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  // OPTIMIZATION: Connection pooling settings
  maxPoolSize: 10,
  minPoolSize: 2,
  maxIdleTimeMS: 60000,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
});

// OPTIMIZATION: Helper function to get collections (reuse pattern)
async function getDb() {
  if (cachedDb) {
    return cachedDb;
  }

  if (!cachedClient) {
    cachedClient = await mongoClient.connect();
    console.log("✅ MongoDB connected (new connection)");
  }

  cachedDb = cachedClient.db(process.env.DB_NAME || 'styledecor');
  return cachedDb;
}

function getCollection(collectionName) {
  if (!cachedDb) {
    throw new Error('Database not initialized');
  }
  return cachedDb.collection(collectionName);
}

// OPTIMIZATION: Non-blocking initialization
// Run index creation and super admin setup in background
let initPromise = null;

async function initializeDatabase() {
  if (initPromise) {
    return initPromise;
  }

  initPromise = (async () => {
    try {
      const db = await getDb();

      // Create indexes in parallel (non-blocking)
      const usersCollection = db.collection('users');
      const servicesCollection = db.collection('services');
      const bookingsCollection = db.collection('bookings');

      await Promise.all([
        usersCollection.createIndex({ email: 1 }, { unique: true, background: true }),
        servicesCollection.createIndex({ service_name: 1 }, { background: true }),
        bookingsCollection.createIndex({ userEmail: 1 }, { background: true })
      ]);

      // OPTIMIZATION: Super admin creation in background (non-blocking)
      setImmediate(async () => {
        try {
          const existingAdmin = await usersCollection.findOne(
            { email: process.env.SUPER_ADMIN_EMAIL },
            { projection: { _id: 1 } }
          );

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
          }
        } catch (error) {
          console.error('❌ Super Admin initialization failed:', error);
        }
      });

      console.log('✅ Database initialized');
    } catch (error) {
      console.error('❌ Database initialization failed:', error);
      initPromise = null;
      throw error;
    }
  })();

  return initPromise;
}

// ============ JWT Middleware ============
// OPTIMIZATION: Check JWT first (faster), then Firebase (slower)
const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    // Try JWT first (faster)
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      return next();
    } catch (jwtError) {
      // If JWT fails, try Firebase (slower)
      try {
        const firebaseAdmin = getFirebaseAdmin();
        const decodedToken = await firebaseAdmin.auth().verifyIdToken(token);
        req.user = decodedToken;
        return next();
      } catch (firebaseError) {
        return res.status(403).json({ message: 'Invalid token' });
      }
    }
  } catch (error) {
    res.status(403).json({ message: 'Token verification failed' });
  }
};

// OPTIMIZATION: Use projection to fetch only role field
const verifyAdmin = async (req, res, next) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const user = await usersCollection.findOne(
      { email: req.user.email },
      { projection: { role: 1 } }
    );

    if (user?.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Authorization check failed' });
  }
};

// OPTIMIZATION: Use projection to fetch only role field
const verifyDecorator = async (req, res, next) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const user = await usersCollection.findOne(
      { email: req.user.email },
      { projection: { role: 1 } }
    );

    if (user?.role !== 'decorator' && user?.role !== 'admin') {
      return res.status(403).json({ message: 'Decorator access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: 'Authorization check failed' });
  }
};

// ============ Routes ============
app.get('/', (req, res) => {
  res.json({
    message: 'StyleDecor API is running',
    status: 'active',
    timestamp: new Date()
  });
});

// ============ Auth Routes ============
app.post('/api/auth/register', async (req, res) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const { email, password, displayName, profileImage } = req.body;

    const existingUser = await usersCollection.findOne(
      { email },
      { projection: { _id: 1 } }
    );

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
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const { email, password, firebaseToken, displayName, profileImage } = req.body;

    // Support Google/Firebase social login by verifying Firebase token and
    // creating a local user if missing.
    if (firebaseToken) {
      try {
        const firebaseAdmin = getFirebaseAdmin();
        const decodedToken = await firebaseAdmin.auth().verifyIdToken(firebaseToken);

        if (decodedToken.email !== email) {
          return res.status(400).json({ message: 'Email mismatch' });
        }

        let user = await usersCollection.findOne({ email });

        if (!user) {
          const newUser = {
            email,
            password: '',
            displayName: displayName || decodedToken.name || email?.split('@')[0] || 'User',
            profileImage: profileImage || decodedToken.picture || '',
            role: 'user',
            createdAt: new Date(),
            isActive: true,
            authProvider: 'google'
          };

          const result = await usersCollection.insertOne(newUser);
          user = { ...newUser, _id: result.insertedId };
        } else if (!user.isActive) {
          return res.status(403).json({ message: 'Account is disabled' });
        }

        const token = jwt.sign(
          { email: user.email, userId: user._id, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '7d' }
        );

        return res.json({
          message: 'Login successful',
          token,
          user: {
            email: user.email,
            displayName: user.displayName,
            role: user.role,
            profileImage: user.profileImage || ''
          }
        });
      } catch (firebaseError) {
        console.error('Firebase login error:', firebaseError);
        return res.status(401).json({ message: 'Invalid Google token' });
      }
    }

    const user = await usersCollection.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(403).json({ message: 'Account is disabled' });
    }

    if (!password) {
      return res.status(400).json({ message: 'Password required' });
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
    await initializeDatabase();
    const usersCollection = getCollection('users');
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

// ============ Image Upload Route ============
app.post('/api/upload-image', async (req, res) => {
  try {
    const { image } = req.body;

    if (!image) {
      return res.status(400).json({ message: 'No image provided' });
    }

    const formData = new URLSearchParams();
    formData.append('key', process.env.IMGBB_API_KEY);
    formData.append('image', image.split(',')[1] || image);

    // OPTIMIZATION: Add timeout to external API call
    const response = await axios.post('https://api.imgbb.com/1/upload', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 10000 // 10 second timeout
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

// ============ Services Routes ============
app.get('/api/services', async (req, res) => {
  try {
    await initializeDatabase();
    const servicesCollection = getCollection('services');
    const { search, category, minPrice, maxPrice, page = 1, limit = 10 } = req.query;

    let query = {};

    if (search) {
      query.service_name = { $regex: search, $options: 'i' };
    }

    if (category) {
      query.service_category = category;
    }

    if (minPrice || maxPrice) {
      query.cost = {};
      if (minPrice) query.cost.$gte = parseFloat(minPrice);
      if (maxPrice) query.cost.$lte = parseFloat(maxPrice);
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    // OPTIMIZATION: Run query and count in parallel
    const [services, total] = await Promise.all([
      servicesCollection
        .find(query)
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      servicesCollection.countDocuments(query)
    ]);

    res.json({
      services,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get services error:', error);
    res.status(500).json({ message: 'Failed to fetch services' });
  }
});

app.get('/api/services/:id', async (req, res) => {
  try {
    await initializeDatabase();
    const servicesCollection = getCollection('services');
    const service = await servicesCollection.findOne({
      _id: new ObjectId(req.params.id)
    });

    if (!service) {
      return res.status(404).json({ message: 'Service not found' });
    }

    res.json(service);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch service' });
  }
});

app.post('/api/services', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const servicesCollection = getCollection('services');
    const { service_name, cost, unit, service_category, description, imageUrl } = req.body;

    const newService = {
      service_name,
      cost: parseFloat(cost),
      unit,
      service_category,
      description,
      imageUrl: imageUrl || '',
      createdByEmail: req.user.email,
      createdAt: new Date(),
      isActive: true
    };

    const result = await servicesCollection.insertOne(newService);

    res.status(201).json({
      message: 'Service created successfully',
      serviceId: result.insertedId
    });
  } catch (error) {
    console.error('Create service error:', error);
    res.status(500).json({ message: 'Failed to create service' });
  }
});

app.put('/api/services/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const servicesCollection = getCollection('services');
    const { service_name, cost, unit, service_category, description, imageUrl } = req.body;

    const updateDoc = {
      $set: {
        service_name,
        cost: parseFloat(cost),
        unit,
        service_category,
        description,
        imageUrl,
        updatedAt: new Date()
      }
    };

    const result = await servicesCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      updateDoc
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'Service not found' });
    }

    res.json({ message: 'Service updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update service' });
  }
});

app.delete('/api/services/:id', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const servicesCollection = getCollection('services');
    const result = await servicesCollection.deleteOne({
      _id: new ObjectId(req.params.id)
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'Service not found' });
    }

    res.json({ message: 'Service deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete service' });
  }
});

// ============ Bookings Routes ============
app.post('/api/bookings', verifyToken, async (req, res) => {
  try {
    await initializeDatabase();
    const servicesCollection = getCollection('services');
    const bookingsCollection = getCollection('bookings');
    const usersCollection = getCollection('users');
    const { serviceId, bookingDate, location, userNotes } = req.body;

    // OPTIMIZATION: Fetch service and user in parallel
    const [service, user] = await Promise.all([
      servicesCollection.findOne({ _id: new ObjectId(serviceId) }),
      usersCollection.findOne(
        { email: req.user.email },
        { projection: { displayName: 1 } }
      )
    ]);

    if (!service) {
      return res.status(404).json({ message: 'Service not found' });
    }

    const newBooking = {
      serviceId: new ObjectId(serviceId),
      serviceName: service.service_name,
      serviceCost: service.cost,
      userEmail: req.user.email,
      userName: user.displayName,
      bookingDate: new Date(bookingDate),
      location,
      userNotes: userNotes || '',
      status: 'pending',
      isPaid: false,
      paymentStatus: 'unpaid',
      assignedDecorator: null,
      createdAt: new Date()
    };

    const result = await bookingsCollection.insertOne(newBooking);

    res.status(201).json({
      message: 'Booking created successfully',
      bookingId: result.insertedId
    });
  } catch (error) {
    console.error('Create booking error:', error);
    res.status(500).json({ message: 'Failed to create booking' });
  }
});

app.get('/api/bookings/my-bookings', verifyToken, async (req, res) => {
  try {
    await initializeDatabase();
    const bookingsCollection = getCollection('bookings');
    const { page = 1, limit = 10 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    // OPTIMIZATION: Run query and count in parallel
    const [bookings, total] = await Promise.all([
      bookingsCollection
        .find({ userEmail: req.user.email })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      bookingsCollection.countDocuments({ userEmail: req.user.email })
    ]);

    res.json({
      bookings,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch bookings' });
  }
});

app.get('/api/bookings', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const bookingsCollection = getCollection('bookings');
    const { page = 1, limit = 10, status, sortBy = 'createdAt' } = req.query;

    let query = {};
    if (status) {
      query.status = status;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    // OPTIMIZATION: Run query and count in parallel
    const [bookings, total] = await Promise.all([
      bookingsCollection
        .find(query)
        .sort({ [sortBy]: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      bookingsCollection.countDocuments(query)
    ]);

    res.json({
      bookings,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch bookings' });
  }
});

app.patch('/api/bookings/:id/status', verifyToken, async (req, res) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const bookingsCollection = getCollection('bookings');
    const { status } = req.body;

    const user = await usersCollection.findOne(
      { email: req.user.email },
      { projection: { role: 1 } }
    );

    if (user.role !== 'admin' && user.role !== 'decorator') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const validStatuses = [
      'pending', 'confirmed', 'assigned', 'planning',
      'materials-prepared', 'on-the-way', 'in-progress',
      'completed', 'cancelled'
    ];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status' });
    }

    const result = await bookingsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          status,
          updatedAt: new Date()
        }
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    res.json({ message: 'Booking status updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update booking status' });
  }
});

app.patch('/api/bookings/:id/assign-decorator', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const bookingsCollection = getCollection('bookings');
    const { decoratorEmail } = req.body;

    const decorator = await usersCollection.findOne(
      { email: decoratorEmail, role: 'decorator' },
      { projection: { _id: 1 } }
    );

    if (!decorator) {
      return res.status(404).json({ message: 'Decorator not found' });
    }

    const result = await bookingsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          assignedDecorator: decoratorEmail,
          status: 'assigned',
          updatedAt: new Date()
        }
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    res.json({ message: 'Decorator assigned successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to assign decorator' });
  }
});

app.patch('/api/bookings/:id/cancel', verifyToken, async (req, res) => {
  try {
    await initializeDatabase();
    const bookingsCollection = getCollection('bookings');
    const booking = await bookingsCollection.findOne({
      _id: new ObjectId(req.params.id)
    });

    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    if (booking.userEmail !== req.user.email) {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    if (booking.status === 'completed' || booking.status === 'cancelled') {
      return res.status(400).json({
        message: 'Cannot cancel completed or already cancelled booking'
      });
    }

    const result = await bookingsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          status: 'cancelled',
          cancelledAt: new Date()
        }
      }
    );

    res.json({ message: 'Booking cancelled successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to cancel booking' });
  }
});

app.get('/api/bookings/my-assignments', verifyToken, verifyDecorator, async (req, res) => {
  try {
    await initializeDatabase();
    const bookingsCollection = getCollection('bookings');
    const bookings = await bookingsCollection
      .find({ assignedDecorator: req.user.email })
      .sort({ bookingDate: 1 })
      .toArray();

    res.json({ bookings });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch assignments' });
  }
});

// ==================== PAYMENT ROUTES ====================

// Create Payment Intent (legacy card form flow)
app.post('/api/payments/create-intent', verifyToken, async (req, res) => {
  try {
    await initializeDatabase();
    const bookingsCollection = getCollection('bookings');
    const { bookingId } = req.body;

    const booking = await bookingsCollection.findOne({
      _id: new ObjectId(bookingId)
    });

    if (!booking) {
      return res.status(404).send({ message: 'Booking not found' });
    }

    if (booking.userEmail !== req.user.email) {
      return res.status(403).send({ message: 'Unauthorized access' });
    }

    if (booking.paymentStatus === 'paid' || booking.isPaid === true) {
      return res.status(400).send({ message: 'Booking already paid' });
    }

    const amountInBDT = booking.serviceCost;
    const amountInUSD = (amountInBDT / 110).toFixed(2);
    const amountInCents = Math.round(parseFloat(amountInUSD) * 100);

    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: 'usd',
      metadata: {
        bookingId: bookingId,
        userEmail: req.user.email,
        originalAmountBDT: amountInBDT.toString(),
      },
      receipt_email: req.user.email,
    });

    res.send({
      clientSecret: paymentIntent.client_secret,
      amount: amountInBDT,
      amountUSD: amountInUSD
    });
  } catch (error) {
    console.error('Payment intent error:', error);
    res.status(500).send({
      message: 'Failed to create payment intent',
      error: error.message
    });
  }
});

// Create Stripe Checkout Session
app.post('/api/payments/create-checkout-session', verifyToken, async (req, res) => {
  try {
    await initializeDatabase();
    const bookingsCollection = getCollection('bookings');
    const { bookingId } = req.body;

    const booking = await bookingsCollection.findOne({
      _id: new ObjectId(bookingId)
    });

    if (!booking) {
      return res.status(404).send({ message: 'Booking not found' });
    }

    if (booking.userEmail !== req.user.email) {
      return res.status(403).send({ message: 'Unauthorized access' });
    }

    if (booking.paymentStatus === 'paid' || booking.isPaid === true) {
      return res.status(400).send({ message: 'Booking already paid' });
    }

    const amountInBDT = booking.serviceCost;
    const amountInUSD = (amountInBDT / 110).toFixed(2);
    const amountInCents = Math.round(parseFloat(amountInUSD) * 100);

    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: booking.serviceName,
              description: `Service booking for ${booking.serviceName}`,
            },
            unit_amount: amountInCents,
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${frontendUrl}/successful?session_id={CHECKOUT_SESSION_ID}&booking_id=${bookingId}`,
      cancel_url: `${frontendUrl}/cancelled?booking_id=${bookingId}`,
      metadata: {
        bookingId: bookingId,
        userEmail: req.user.email,
        originalAmountBDT: amountInBDT.toString(),
      },
      customer_email: req.user.email,
    });

    res.send({
      sessionId: session.id,
      url: session.url,
      amount: amountInBDT,
      amountUSD: amountInUSD
    });
  } catch (error) {
    console.error('Checkout session error:', error);
    res.status(500).send({
      message: 'Failed to create checkout session',
      error: error.message
    });
  }
});

// Verify payment and update booking (called from success page)
app.post('/api/payments/verify-session', verifyToken, async (req, res) => {
  try {
    await initializeDatabase();
    const bookingsCollection = getCollection('bookings');
    const paymentsCollection = getCollection('payments');
    const { sessionId, bookingId } = req.body;

    const session = await stripe.checkout.sessions.retrieve(sessionId);

    if (session.payment_status !== 'paid') {
      return res.status(400).send({ message: 'Payment not completed' });
    }

    const booking = await bookingsCollection.findOne({
      _id: new ObjectId(bookingId)
    });

    if (!booking) {
      return res.status(404).send({ message: 'Booking not found' });
    }

    if (booking.userEmail !== req.user.email) {
      return res.status(403).send({ message: 'Unauthorized access' });
    }

    if (booking.paymentStatus === 'paid' || booking.isPaid === true) {
      return res.send({
        message: 'Payment already confirmed',
        success: true
      });
    }

    // OPTIMIZATION: Run booking update and payment insert in parallel
    const paymentRecord = {
      bookingId: new ObjectId(bookingId),
      userEmail: req.user.email,
      amount: parseFloat(booking.serviceCost),
      amountUSD: (parseFloat(booking.serviceCost) / 110).toFixed(2),
      paymentIntentId: session.payment_intent,
      sessionId: sessionId,
      currency: 'usd',
      status: 'completed',
      createdAt: new Date()
    };

    await Promise.all([
      bookingsCollection.updateOne(
        { _id: new ObjectId(bookingId) },
        {
          $set: {
            isPaid: true,
            paymentStatus: 'paid',
            status: 'confirmed',
            paidAt: new Date(),
            updatedAt: new Date()
          }
        }
      ),
      paymentsCollection.insertOne(paymentRecord)
    ]);

    res.send({
      message: 'Payment verified and confirmed successfully',
      success: true
    });
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).send({
      message: 'Failed to verify payment',
      error: error.message
    });
  }
});

// Confirm Payment
app.post('/api/payments/confirm', verifyToken, async (req, res) => {
  try {
    await initializeDatabase();
    const bookingsCollection = getCollection('bookings');
    const paymentsCollection = getCollection('payments');
    const { bookingId, paymentIntentId, amount } = req.body;

    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);

    if (paymentIntent.status !== 'succeeded') {
      return res.status(400).send({ message: 'Payment not successful' });
    }

    // OPTIMIZATION: Run booking update and payment insert in parallel
    const paymentRecord = {
      bookingId: new ObjectId(bookingId),
      userEmail: req.user.email,
      amount: parseFloat(amount),
      amountUSD: (parseFloat(amount) / 110).toFixed(2),
      paymentIntentId,
      currency: 'usd',
      status: 'completed',
      createdAt: new Date()
    };

    const [, result] = await Promise.all([
      bookingsCollection.updateOne(
        { _id: new ObjectId(bookingId) },
        {
          $set: {
            isPaid: true,
            paymentStatus: 'paid',
            status: 'confirmed',
            paidAt: new Date(),
            updatedAt: new Date()
          }
        }
      ),
      paymentsCollection.insertOne(paymentRecord)
    ]);

    res.send({
      message: 'Payment confirmed successfully',
      success: true,
      paymentId: result.insertedId
    });
  } catch (error) {
    console.error('Payment confirmation error:', error);
    res.status(500).send({
      message: 'Failed to confirm payment',
      error: error.message
    });
  }
});

// Get User's Payment History
app.get('/api/payments/my-payments', verifyToken, async (req, res) => {
  try {
    await initializeDatabase();
    const paymentsCollection = getCollection('payments');
    const userEmail = req.user.email;
    const payments = await paymentsCollection
      .find({ userEmail })
      .sort({ createdAt: -1 })
      .toArray();

    res.send({ payments });
  } catch (error) {
    console.error('Fetch payments error:', error);
    res.status(500).send({
      message: 'Failed to fetch payments',
      error: error.message
    });
  }
});

// Get All Payments (Admin only)
app.get('/api/payments', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const paymentsCollection = getCollection('payments');
    const payments = await paymentsCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.send(payments);
  } catch (error) {
    console.error('Fetch all payments error:', error);
    res.status(500).send({
      message: 'Failed to fetch payments',
      error: error.message
    });
  }
});

// ============ User Management Routes ============
app.get('/api/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const { search, role, page = 1, limit = 10 } = req.query;

    let query = {};

    // Filter by role if specified
    if (role && role !== 'all') {
      query.role = role;
    }

    // Search by name or email
    if (search) {
      query.$or = [
        { displayName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    // Run query and count in parallel
    const [users, total] = await Promise.all([
      usersCollection
        .find(query, { projection: { password: 0 } })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .toArray(),
      usersCollection.countDocuments(query)
    ]);

    res.json({
      users,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

// ============ Decorator Management Routes ============
app.get('/api/decorators', async (req, res) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const { search } = req.query;
    let query = { role: 'decorator' };

    if (search) {
      query.displayName = { $regex: search, $options: 'i' };
    }

    const decorators = await usersCollection
      .find(query, { projection: { password: 0 } })
      .toArray();

    res.json({ decorators });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch decorators' });
  }
});

app.patch('/api/users/:email/make-decorator', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const { email } = req.params;
    const { specialty, rating, experience } = req.body;

    const result = await usersCollection.updateOne(
      { email },
      {
        $set: {
          role: 'decorator',
          specialty: specialty || '',
          rating: rating || 0,
          experience: experience || '',
          updatedAt: new Date()
        }
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User role updated to decorator successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update user role' });
  }
});

app.patch('/api/users/:email/toggle-role', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const { email } = req.params;
    const { specialty, rating, experience } = req.body;

    // Get current user
    const user = await usersCollection.findOne(
      { email },
      { projection: { role: 1 } }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Prevent toggling admin role
    if (user.role === 'admin') {
      return res.status(403).json({ message: 'Cannot toggle admin role' });
    }

    let updateDoc = {};
    let newRole = '';

    if (user.role === 'user') {
      // Promote to decorator
      newRole = 'decorator';
      updateDoc = {
        $set: {
          role: 'decorator',
          specialty: specialty || '',
          rating: parseFloat(rating) || 0,
          experience: experience || '',
          isActive: true,
          updatedAt: new Date()
        }
      };
    } else if (user.role === 'decorator') {
      // Demote to user
      newRole = 'user';
      updateDoc = {
        $set: {
          role: 'user',
          updatedAt: new Date()
        },
        $unset: {
          specialty: '',
          rating: '',
          experience: ''
        }
      };
    }

    const result = await usersCollection.updateOne({ email }, updateDoc);

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      message: `User role updated to ${newRole} successfully`,
      newRole
    });
  } catch (error) {
    console.error('Toggle role error:', error);
    res.status(500).json({ message: 'Failed to toggle user role' });
  }
});

app.patch('/api/decorators/:email/toggle-status', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const { email } = req.params;

    const user = await usersCollection.findOne(
      { email, role: 'decorator' },
      { projection: { isActive: 1 } }
    );

    if (!user) {
      return res.status(404).json({ message: 'Decorator not found' });
    }

    const result = await usersCollection.updateOne(
      { email },
      {
        $set: {
          isActive: !user.isActive,
          updatedAt: new Date()
        }
      }
    );

    res.json({
      message: `Decorator ${user.isActive ? 'disabled' : 'enabled'} successfully`,
      isActive: !user.isActive
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to toggle decorator status' });
  }
});

// ============ Analytics Routes ============
app.get('/api/analytics/stats', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const usersCollection = getCollection('users');
    const servicesCollection = getCollection('services');
    const bookingsCollection = getCollection('bookings');
    const paymentsCollection = getCollection('payments');

    // OPTIMIZATION: Run all count queries in parallel
    const [
      totalUsers,
      totalDecorators,
      totalServices,
      totalBookings,
      completedBookings,
      pendingBookings,
      payments
    ] = await Promise.all([
      usersCollection.countDocuments({ role: 'user' }),
      usersCollection.countDocuments({ role: 'decorator' }),
      servicesCollection.countDocuments(),
      bookingsCollection.countDocuments(),
      bookingsCollection.countDocuments({ status: 'completed' }),
      bookingsCollection.countDocuments({ status: 'pending' }),
      paymentsCollection.find({ status: 'completed' }).toArray()
    ]);

    const totalRevenue = payments.reduce((sum, payment) => sum + payment.amount, 0);

    res.json({
      totalUsers,
      totalDecorators,
      totalServices,
      totalBookings,
      completedBookings,
      pendingBookings,
      totalRevenue
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch statistics' });
  }
});

app.get('/api/analytics/service-demand', verifyToken, verifyAdmin, async (req, res) => {
  try {
    await initializeDatabase();
    const bookingsCollection = getCollection('bookings');
    const serviceDemand = await bookingsCollection.aggregate([
      {
        $group: {
          _id: '$serviceName',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      },
      {
        $limit: 10
      }
    ]).toArray();

    res.json({ serviceDemand });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch service demand data' });
  }
});

// ============ Error Handling ============
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// ============ Server Start (Only for local development) ============
// OPTIMIZATION: Don't listen in production (Vercel serverless)
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

// Graceful shutdown (only relevant for local development)
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  if (cachedClient) {
    await cachedClient.close();
  }
  process.exit(0);
});

// OPTIMIZATION: Export app for Vercel serverless
module.exports = app;