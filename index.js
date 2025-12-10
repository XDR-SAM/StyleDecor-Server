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
app.use(cors({
  origin: [process.env.FRONTEND_URL, 'http://localhost:5173', 'http://localhost:5174' , 'https://magical-dusk-71097f.netlify.app'],
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
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
} async function initializeSuperAdmin() {
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