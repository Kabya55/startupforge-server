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
