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

// RBAC Middlewares
const verifyCollaborator = async (req, res, next) => {
  if (req.user?.role !== "collaborator") {
    return res.status(403).send({ message: "forbidden access" });
  }
  next();
};

const verifyFounder = async (req, res, next) => {
  if (req.user?.role !== "founder") {
    return res.status(403).send({ message: "forbidden access" });
  }
  next();
};

const verifyAdmin = async (req, res, next) => {
  if (req.user?.role !== "admin") {
    return res.status(403).send({ message: "forbidden access" });
  }
  next();
};

// GET /
// Root endpoint to verify that the StartupForge Backend API is running.
app.get("/", (req, res) => {
  res.send("StartupForge Backend API is running!");
});


// GET /api/plans
// Retrieve details of plans. Returns a single plan if plan_id query parameter is specified, otherwise returns plan details.
app.get("/api/plans", async (req, res) => {
  try {
    const query = {};
    if (req.query.plan_id) {
      query.id = req.query.plan_id;
    }
    const plan = await planCollection.findOne(query);
    res.send(plan || { message: "Plan not found" });
  } catch (error) {
    res.status(500).send({ message: "Error fetching plan", error: error.message });
  }
});

// POST /api/payments/create-checkout-session
// Create a Stripe Checkout Session with dynamic pricing and metadata based on the selected package.
app.post("/api/payments/create-checkout-session", async (req, res) => {
  const { email, packageId } = req.body;
  if (!email || !packageId) {
    return res.status(400).send({ message: "email and packageId are required" });
  }

  let unitAmount = 0;
  let packageName = "";

  // Map prices in cents according to the package ID selected on the frontend
  if (packageId === "founder_growth") {
    unitAmount = 4900;
    packageName = "StartupForge Growth Plan";
  } else if (packageId === "founder_enterprise") {
    unitAmount = 14900;
    packageName = "StartupForge Enterprise Plan";
  } else if (packageId === "collaborator_pro") {
    unitAmount = 1999;
    packageName = "StartupForge Collaborator Pro";
  } else if (packageId === "collaborator_premium") {
    unitAmount = 3999;
    packageName = "StartupForge Collaborator Premium";
  } else {
    return res.status(400).send({ message: "Invalid or Free package selected" });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: packageName,
              description: "Upgrade your account package tier.",
            },
            unit_amount: unitAmount,
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `${process.env.CLIENT_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/packages`,
      customer_email: email,
      // Save packageId in metadata for the success callback page
      metadata: {
        packageId: packageId,
      },
    });

    res.send({ id: session.id, url: session.url });
  } catch (err) {
    console.error("Stripe session creation error:", err);
    res.status(500).send({ message: "Stripe error", error: err.message });
  }
});

// POST /api/payments/confirm
// Verify Stripe payment using checkout session ID and upgrade the user's plan tier (case-insensitive email matching).
app.post("/api/payments/confirm", async (req, res) => {
  const { session_id } = req.body;
  if (!session_id) {
    return res.status(400).send({ message: "session_id is required" });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (session.payment_status !== "paid") {
      return res.status(400).send({ message: "Payment was not successful" });
    }

    // Prevent duplicate payment transaction processing
    const existing = await paymentCollection.findOne({ transaction_id: session.id });
    if (existing) {
      return res.send({ success: true, message: "Payment already processed", payment: existing });
    }

    const email = session.customer_details?.email || session.customer_email;
    const purchasedPackage = session.metadata?.packageId;

    if (!email) {
      return res.status(400).send({ message: "No customer email associated with this session" });
    }

    // A) Store the transaction details including the purchased package tier in the Payments collection
    const paymentRecord = {
      user_email: email,
      amount: session.amount_total / 100,
      package_id: purchasedPackage || "unknown_package",
      transaction_id: session.id,
      payment_status: "Paid",
      paid_at: new Date(),
    };
    await paymentCollection.insertOne(paymentRecord);

    // B) Directly update the new subscription package in the Users collection (case-insensitive email matching)
    if (purchasedPackage) {
      const userUpdateResult = await usersCollection.updateOne(
        { email: { $regex: `^${email}$`, $options: "i" } },
        {
          $set: {
            package: purchasedPackage,
            isPremium: true,
            updatedAt: new Date()
          }
        }
      );
    }

    res.send({
      success: true,
      message: `Payment recorded and profile package updated to ${purchasedPackage}`,
      payment: paymentRecord
    });
  } catch (err) {
    console.error("Payment confirmation error:", err);
    res.status(500).send({ message: "Payment confirmation failed", error: err.message });
  }
});

// POST /api/startups
// Create/register a new startup profile (founder only).
app.post("/api/startups", verifyToken, verifyFounder, async (req, res) => {
  const startup = req.body;
  const newStartup = {
    ...startup,
    status: "pending",
    createdAt: new Date(),
  };
  const result = await startupCollection.insertOne(newStartup);
  res.send(result);
});

// GET /api/startups
// Retrieve startup profiles, optionally filtered by status query parameter.
app.get("/api/startups", async (req, res) => {
  const query = {};
  if (req.query.status) {
    query.status = req.query.status;
  }
  const cursor = startupCollection.find(query);
  const startups = await cursor.toArray();

  for (const startup of startups) {
    const filter = { startup_id: startup._id.toString() };
    const opportunityCount = await opportunityCollection.countDocuments(filter);
    startup.opportunityCount = opportunityCount;

    // Fetch founder name dynamically
    if (startup.founder_email) {
      const founder = await usersCollection.findOne({
        email: { $regex: `^${startup.founder_email}$`, $options: "i" }
      });
      startup.founder_name = founder ? founder.name : "Unknown Founder";
    } else {
      startup.founder_name = "Unknown Founder";
    }
  }
  res.send(startups);
});

// GET /api/my/startups
// Retrieve the startup profile associated with the currently logged-in founder.
app.get("/api/my/startups", verifyToken, verifyFounder, async (req, res) => {
  const query = { founder_email: req.user.email };
  const result = await startupCollection.findOne(query);
  res.send(result || {});