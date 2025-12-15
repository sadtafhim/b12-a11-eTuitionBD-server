// backend/server.js
const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n").replace(
      /^"|"$/g,
      ""
    ),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
  }),
});

// Middleware
app.use(cors());
app.use(express.json());

// Firebase Token Verification Middleware
const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send({ message: "Unauthorized access" });

  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    console.error("Firebase token verification failed:", err);
    return res.status(401).send({ message: "Unauthorized access" });
  }
};

// MongoDB Connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.h1ahmwn.mongodb.net/eTuitionBD_db?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB!");

    const db = client.db("eTuitionBD_db");
    const tuitionCollection = db.collection("tuitions");
    const userCollection = db.collection("users");

    // ===== User Routes =====
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;
        user.role = user.role || "student";
        user.createdAt = new Date();
        const email = user.email;
        const userExists = await userCollection.findOne({ email });
        if (userExists) {
          return res.send({ message: "user exists" });
        }

        const result = await userCollection.insertOne(user);
        console.log("User registered:", user.email);
        res.send({ insertedId: result.insertedId });
      } catch (err) {
        console.error("Error creating user:", err);
        res.status(500).send({ message: "Failed to create user" });
      }
    });

    // ===== Tuition Routes =====

    // Get all tuitions or by user email
    app.get("/tuitions", verifyFBToken, async (req, res) => {
      try {
        const { email } = req.query;
        const query = email ? { email } : {};

        if (email && email !== req.decoded_email) {
          return res.status(403).send({ message: "Forbidden access" });
        }

        const tuitions = await tuitionCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();
        res.send(tuitions);
      } catch (err) {
        console.error("Error fetching tuitions:", err);
        res.status(500).send({ message: "Failed to fetch tuitions" });
      }
    });

    // Get single tuition by ID
    app.get("/tuitions/:id", async (req, res) => {
      try {
        const tuition = await tuitionCollection.findOne({
          _id: new ObjectId(req.params.id),
        });
        if (!tuition)
          return res.status(404).send({ message: "Tuition not found" });
        res.send(tuition);
      } catch (err) {
        console.error("Error fetching tuition:", err);
        res.status(400).send({ message: "Invalid tuition ID" });
      }
    });

    // Create new tuition
    app.post("/tuitions", async (req, res) => {
      try {
        const tuition = req.body;
        tuition.createdAt = new Date();

        const result = await tuitionCollection.insertOne(tuition);
        res.send({ insertedId: result.insertedId });
      } catch (err) {
        console.error("Error creating tuition:", err);
        res.status(500).send({ message: "Failed to create tuition" });
      }
    });

    // Update tuition
    app.patch("/tuitions/:id", async (req, res) => {
      try {
        const updatedDoc = req.body;
        const result = await tuitionCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              ...updatedDoc,
              status: "pending",
              updatedAt: new Date().toISOString(),
            },
          }
        );
        res.send(result);
      } catch (err) {
        console.error("Error updating tuition:", err);
        res.status(500).send({ message: "Failed to update tuition" });
      }
    });

    // Delete tuition
    app.delete("/tuitions/:id", async (req, res) => {
      try {
        const result = await tuitionCollection.deleteOne({
          _id: new ObjectId(req.params.id),
        });
        res.send(result);
      } catch (err) {
        console.error("Error deleting tuition:", err);
        res.status(500).send({ message: "Failed to delete tuition" });
      }
    });
  } catch (err) {
    console.error("MongoDB connection failed:", err);
  }
}

run().catch(console.error);

// Health check route
app.get("/", (req, res) => {
  res.send("eTuitionBD Server is Running!");
});

// Start server
app.listen(port, () => console.log(`Server running on port ${port}`));
