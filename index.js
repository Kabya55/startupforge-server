require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: [process.env.CLIENT_URL, "http://localhost:3000"],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const uri = process.env.MONGO_DB_URI;

// Create a MongoClient
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

client.connect()
  .catch(err => console.error("Database connection error:", err));

// Database case set to: [StartupForge]
const database = client.db("StartupForge");

const opportunityCollection = database.collection("Opportunities");
const startupCollection = database.collection("Startups");
const applicationCollection = database.collection("Applications");
const paymentCollection = database.collection("Payments");
const planCollection = database.collection("plans");
const usersCollection = database.collection("user");
const sessionCollection = database.collection("session");
const subscriptionCollection = database.collection("subscriptions");

// Authentication middleware using Better Auth session in database
async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    let token = null;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.substring(7);
    } else {
      token = req.cookies.jwt_token || req.cookies.token || req.cookies["better-auth.session_token"] || req.cookies["__Secure-better-auth.session_token"];
    }

    if (!token) {
      return res.status(401).json({ error: "Authentication required" });
    }

    // 1. Try finding by full token
    let session = await sessionCollection.findOne({ token: token });

    // 2. Try finding by split token (Better Auth signs cookies: token.signature)
    if (!session && token.includes(".")) {
      const actualToken = token.split(".")[0];
      session = await sessionCollection.findOne({ token: actualToken });
    }

    // 3. Fallback: Ask Next.js Better Auth API directly (handles hashes/encryption)
    if (!session) {
      const authUrl = process.env.CLIENT_URL;
      try {
        const response = await fetch(`${authUrl}/api/auth/get-session`, {
          headers: {
            "Authorization": `Bearer ${token}`,
            "cookie": `better-auth.session_token=${token}`
          }
        });
        const authData = await response.json();
        if (authData && authData.session && authData.user) {
          session = authData.session;
          session.userId = authData.user.id;
        }
      } catch (err) {
        console.error("Error communicating with Better Auth API:", err);
      }
    }

    if (!session) {
      return res.status(401).json({ error: "Session invalid or expired" });
    }

    // Check expiration date (handle both Date object from DB and string from API)
    if (session.expiresAt && new Date(session.expiresAt) < new Date()) {
      return res.status(401).json({ error: "Session invalid or expired" });
    }

    // Find the user associated with the session
    let user = null;
    if (session.userId) {
      if (ObjectId.isValid(session.userId)) {
        user = await usersCollection.findOne({
          $or: [
            { _id: new ObjectId(session.userId) },
            { id: session.userId }
          ]
        });
      } else {
        user = await usersCollection.findOne({ id: session.userId });
      }
    }

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    if (user.isBlocked) {
      return res.status(403).json({ error: "Your account is blocked by the administrator." });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(500).json({ error: "Internal server error during authentication" });
  }
}
