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
});

// GET /api/startups/count
// Retrieve the total count of startups.
app.get("/api/startups/count", async (req, res) => {
  try {
    const count = await startupCollection.countDocuments();
    res.send({ totalStartups: count });
  } catch (error) {
    res.status(500).send({ message: "Failed to get count", error: error.message });
  }
});

// GET /api/startups/:id
// Retrieve a specific startup profile by its database ObjectId.
app.get("/api/startups/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await startupCollection.findOne(query);
    if (result) {
      const filter = { startup_id: result._id.toString() };
      const opportunityCount = await opportunityCollection.countDocuments(filter);
      result.opportunityCount = opportunityCount;

      if (result.founder_email) {
        const founder = await usersCollection.findOne({
          email: { $regex: `^${result.founder_email}$`, $options: "i" }
        });
        result.founder_name = founder ? founder.name : "Unknown Founder";
      } else {
        result.founder_name = "Unknown Founder";
      }
    }
    res.send(result);
  } catch (err) {
    res.status(400).send({ message: "Invalid ID format" });
  }
});

// PATCH /api/startups/:id
// Update a founder's startup profile. The operation validates that the logged-in founder is the owner.
app.patch("/api/startups/:id", verifyToken, verifyFounder, async (req, res) => {
  try {
    const id = req.params.id;
    const update = req.body;
    const filter = { _id: new ObjectId(id), founder_email: req.user.email };
    const updateDoc = {
      $set: {
        startup_name: update.startup_name,
        logo: update.logo,
        industry: update.industry,
        description: update.description,
        funding_stage: update.funding_stage
      }
    };
    const result = await startupCollection.updateOne(filter, updateDoc);
    res.send(result);
  } catch (err) {
    res.status(400).send({ message: "Update failed" });
  }
});

// PATCH /api/startups/:id/status
// Update a startup profile status (e.g. approved, rejected) (admin only).
app.patch("/api/startups/:id/status", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body;

    if (!status) {
      return res.status(400).send({ message: "Status is required" });
    }

    const filter = { _id: new ObjectId(id) };
    const updateDoc = {
      $set: {
        status: status
      }
    };
    const result = await startupCollection.updateOne(filter, updateDoc);

    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "Startup not found" });
    }

    res.send(result);
  } catch (err) {
    res.status(500).send({ message: "Status update failed", error: err.message });
  }
});

// DELETE /api/startups/:id
// Delete a startup profile. Validates that the logged-in founder is the owner.
app.delete("/api/startups/:id", verifyToken, verifyFounder, async (req, res) => {
  try {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id), founder_email: req.user.email };
    const result = await startupCollection.deleteOne(filter);
    res.send(result);
  } catch (err) {
    res.status(400).send({ message: "Delete failed" });
  }
});

// POST /api/opportunities
// Create a new opportunity post (founder only, subject to subscription package limits).
app.post("/api/opportunities", verifyToken, verifyFounder, async (req, res) => {
  const opportunity = req.body;

  const startup = await startupCollection.findOne({ founder_email: req.user.email });
  if (!startup) {
    return res.status(400).send({ message: "You must create a startup profile first before posting opportunities." });
  }

  if (startup.status?.toLowerCase() !== "approved") {
    return res.status(403).send({ message: "Your startup profile must be approved by an Admin before you can post opportunities." });
  }

  const userPackageId = req.user.package || "founder_free";
  const planConfig = await planCollection.findOne({ id: userPackageId });

  let maxLimit = 3;
  if (planConfig) {
    maxLimit = planConfig.maxOpportunityPostsPerMonth;
  } else if (userPackageId === "premium" || req.user.isPremium) {
    maxLimit = null;
  }

  if (maxLimit !== null) {
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);

    const currentMonthCount = await opportunityCollection.countDocuments({
      founder_email: req.user.email,
      createdAt: { $gte: startOfMonth }
    });

    if (currentMonthCount >= maxLimit) {
      return res.status(403).send({
        message: `Opportunity post limit reached! You can only post ${maxLimit} opportunities per month on the ${planConfig?.name || "Free"} plan. Please upgrade your package to post more.`
      });
    }
  }

  const newOpportunity = {
    ...opportunity,
    startup_id: startup._id.toString(),
    startup_name: startup.startup_name,
    // Save the industry value sent from the form
    industry: opportunity.industry,
    founder_email: req.user.email,
    createdAt: new Date(),
  };

  const result = await opportunityCollection.insertOne(newOpportunity);
  res.send(result);
});

// GET /api/opportunities
// Query opportunities list with optional search filters, sorting, and pagination.
app.get("/api/opportunities", async (req, res) => {
  const query = {};
  const conditions = [];

  if (req.query.search) {
    conditions.push({
      $or: [
        { role_title: { $regex: req.query.search, $options: "i" } },
        { required_skills: { $regex: req.query.search, $options: "i" } }
      ]
    });
  }

  if (req.query.work_style) {
    const workStyles = req.query.work_style.split(",").map(style => new RegExp(`^${style}$`, "i"));
    conditions.push({ work_type: { $in: workStyles } });
  }

  if (req.query.work_type) {
    const workTypes = req.query.work_type.split(",").map(type => new RegExp(`^${type}$`, "i"));
    conditions.push({ work_type: { $in: workTypes } });
  }

  if (req.query.industry) {
    const industries = req.query.industry.split(",").map(ind => new RegExp(`^${ind}$`, "i"));
    conditions.push({ industry: { $in: industries } });
  }

  if (req.query.founder_email) {
    conditions.push({ founder_email: req.query.founder_email });
  }

  if (req.query.startup_id) {
    conditions.push({ startup_id: req.query.startup_id });
  }

  if (conditions.length > 0) {
    query.$and = conditions;
  }

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 6;
  const skip = (page - 1) * limit;

  const total = await opportunityCollection.countDocuments(query);
  const cursor = opportunityCollection.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit);
  const opportunities = await cursor.toArray();

  res.send({ total, opportunities });
});

// GET /api/opportunities/count
// Retrieve the total count of opportunities in the database.
app.get("/api/opportunities/count", async (req, res) => {
  try {
    const count = await opportunityCollection.countDocuments();
    res.send({ totalOpportunities: count });
  } catch (error) {
    res.status(500).send({ message: "Failed to get count", error: error.message });
  }
});

// GET /api/opportunities/:id
// Retrieve a specific opportunity by its database ObjectId.
app.get("/api/opportunities/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const result = await opportunityCollection.findOne({ _id: new ObjectId(id) });
    res.send(result);
  } catch (err) {
    res.status(400).send({ message: "Invalid ID format" });
  }
});

// PATCH /api/opportunities/:id
// Update a specific opportunity's details. Validates that the logged-in founder is the owner.
app.patch("/api/opportunities/:id", verifyToken, verifyFounder, async (req, res) => {
  try {
    const id = req.params.id;
    const update = req.body;
    const filter = { _id: new ObjectId(id), founder_email: req.user.email };
    const updateDoc = {
      $set: {
        role_title: update.role_title,
        required_skills: update.required_skills,
        work_type: update.work_type,
        commitment_level: update.commitment_level,
        deadline: update.deadline,
        description: update.description,
        minSalary: update.minSalary,
        maxSalary: update.maxSalary,
        work_style: update.work_style,
        location: update.location,
        industry: update.industry
      }
    };
    const result = await opportunityCollection.updateOne(filter, updateDoc);
    res.send(result);
  } catch (err) {
    res.status(400).send({ message: "Update failed" });
  }
});

// DELETE /api/opportunities/:id
// Delete a specific opportunity. Validates that the logged-in founder is the owner.
app.delete("/api/opportunities/:id", verifyToken, verifyFounder, async (req, res) => {
  try {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id), founder_email: req.user.email };
    const result = await opportunityCollection.deleteOne(filter);
    res.send(result);
  } catch (err) {
    res.status(400).send({ message: "Delete failed" });
  }
});

// POST /api/applications
// Submit a job application to a specific opportunity, checking monthly subscription application limits.
app.post("/api/applications", verifyToken, async (req, res) => {
  const application = req.body;
  const applicant_email = req.user.email;

  if (!applicant_email) {
    return res.status(400).send({ message: "applicant_email is required" });
  }

  try {
    const userPackageId = req.user.package || "collaborator_free";
    const planConfig = await planCollection.findOne({ id: userPackageId });

    let maxLimit = 3;
    if (planConfig) {
      maxLimit = planConfig.maxApplicationsPerMonth;
    } else if (userPackageId === "premium" || req.user.isPremium) {
      maxLimit = null;
    }

    if (maxLimit !== null) {
      const startOfMonth = new Date();
      startOfMonth.setDate(1);
      startOfMonth.setHours(0, 0, 0, 0);

      const currentMonthCount = await applicationCollection.countDocuments({
        applicant_email: applicant_email,
        applied_at: { $gte: startOfMonth }
      });

      if (currentMonthCount >= maxLimit) {
        return res.status(403).send({
          message: `Limit reached! You can only apply to ${maxLimit} opportunities per month on the ${planConfig?.name || "Free"} plan. Please upgrade your package to apply more.`
        });
      }
    }

    const existing = await applicationCollection.findOne({
      opportunity_id: application.opportunity_id,
      applicant_email: applicant_email
    });

    if (existing) {
      return res.status(400).send({ message: "You have already applied to this opportunity." });
    }

    const opp = await opportunityCollection.findOne({ _id: new ObjectId(application.opportunity_id) });
    if (!opp) {
      return res.status(404).send({ message: "Opportunity not found" });
    }

    const newApplication = {
      opportunity_id: application.opportunity_id,
      role_title: opp.role_title,
      startup_name: opp.startup_name,
      founder_email: opp.founder_email,
      applicant_email: applicant_email,
      portfolio_link: application.portfolio_link,
      motivation: application.motivation,
      status: "Pending",
      applied_at: new Date(),
    };

    const result = await applicationCollection.insertOne(newApplication);
    res.send(result);

  } catch (err) {
    console.error("Application submission error:", err);
    res.status(500).send({ message: "Failed to submit application", error: err.message });
  }
});

// GET /api/applications
// Retrieve application history based on the user's role (collaborator: their applications; founder: applications to their startup; admin: all).
app.get("/api/applications", verifyToken, async (req, res) => {
  const query = {};

  if (req.user.role === "collaborator") {
    query.applicant_email = req.user.email;
  } else if (req.user.role === "founder") {
    query.founder_email = req.user.email;
  } else if (req.user.role === "admin") {
    // Admin pipeline
  } else {
    return res.status(403).send({ message: "forbidden access" });
  }

  const cursor = applicationCollection.find(query).sort({ applied_at: -1 });
  const result = await cursor.toArray();
  res.send(result);
});

// PATCH /api/applications/:id/status
// Update application status (Accepted/Rejected) (founder only).
app.patch("/api/applications/:id/status", verifyToken, verifyFounder, async (req, res) => {
  try {
    const id = req.params.id;
    const { status } = req.body;
    if (!["Accepted", "Rejected"].includes(status)) {
      return res.status(400).send({ message: "Invalid status value" });
    }

    const filter = { _id: new ObjectId(id), founder_email: req.user.email };
    const result = await applicationCollection.updateOne(filter, { $set: { status } });
    res.send(result);
  } catch (err) {
    res.status(400).send({ message: "Status update failed" });
  }
});

// GET /api/payments
// Retrieve list of all payment records (admin only).
app.get("/api/payments", verifyToken, verifyAdmin, async (req, res) => {
  const result = await paymentCollection.find().sort({ paid_at: -1 }).toArray();
  res.send(result);
});

// PATCH /api/users/profile
// Update the current user's profile details (name, image, skills, bio).
app.patch("/api/users/profile", verifyToken, async (req, res) => {
  try {
    const email = req.user.email;
    const { name, image, skills, bio } = req.body;
    const updateDoc = {
      $set: { name, image, skills, bio }
    };
    const result = await usersCollection.updateOne({ email }, updateDoc);
    res.send(result);
  } catch (err) {
    res.status(400).send({ message: "Failed to update profile", error: err.message });
  }
});

// GET /api/users/profile
// Retrieve current logged-in user profile details.
app.get("/api/users/profile", verifyToken, async (req, res) => {
  res.send(req.user);
});

// GET /api/users
// Retrieve all registered user accounts (admin only).
app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
  const result = await usersCollection.find().toArray();
  res.send(result);
});

// PATCH /api/users/:id/block
// Block a specific user by setting isBlocked flag (admin only).
app.patch("/api/users/:id/block", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const result = await usersCollection.updateOne(filter, { $set: { isBlocked: true } });
    res.send(result);