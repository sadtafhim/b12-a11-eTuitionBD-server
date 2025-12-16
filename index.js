// backend/server.js
const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

// Initialize Firebase Admin (Configuration left as is, assuming ENV variables are correct)
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

// MongoDB Connection Setup
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.h1ahmwn.mongodb.net/eTuitionBD_db?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let userCollection;
let tuitionCollection;

// Firebase Token Verification Middleware (CRITICAL FIX)
const verifyFBToken = async (req, res, next) => {
  const authorizationHeader = req.headers.authorization;
  if (!authorizationHeader || !authorizationHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .send({ message: "Unauthorized access: No token provided" });
  }

  try {
    const idToken = authorizationHeader.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    const userEmail = decoded.email;

    // 1. Attach decoded email
    req.decoded_email = userEmail;

    // 2. Fetch user from DB and attach full user object (including role) to req.user
    // THIS FIXES THE "Cannot read property 'role' of undefined" 500 ERROR
    const user = await userCollection.findOne({ email: userEmail });
    if (!user) {
      return res
        .status(403)
        .send({ message: "Forbidden: User record missing." });
    }
    req.user = user; // Now routes can safely access req.user.role

    next();
  } catch (err) {
    console.error("Firebase token verification failed:", err);
    return res
      .status(401)
      .send({ message: "Unauthorized access: Invalid token" });
  }
};

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB!");

    const db = client.db("eTuitionBD_db");
    tuitionCollection = db.collection("tuitions");
    userCollection = db.collection("users");

    // ===== User Routes (Mostly untouched, minor refactor) =====

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

    app.get("/users", verifyFBToken, async (req, res) => {
      try {
        const { email } = req.query;
        const userRole = req.user.role;

        let query = {};

        if (email) {
          if (email !== req.decoded_email) {
            return res
              .status(403)
              .send({ message: "Forbidden access: Email mismatch" });
          }
          query = { email };
        } else {
          if (userRole !== "admin") {
            return res.status(403).send({
              message:
                "Forbidden access: Requires Admin role to view all users",
            });
          }
        }

        const users = await userCollection
          .find(query)
          .sort({ createdAt: -1 })
          .toArray();

        if (email) {
          res.send(users[0] || {}); // Send single user object
        } else {
          res.send(users); // Send array of all users
        }
      } catch (err) {
        console.error("Error fetching user(s):", err);
        res.status(500).send({ message: "Failed to fetch user(s)" });
      }
    });

    app.get("/users/:id", verifyFBToken, async (req, res) => {
      const userId = req.params.id;

      // 1. Basic check for ID format before attempting MongoDB conversion
      if (!ObjectId.isValid(userId)) {
        console.error("Invalid user ID format received:", userId);
        return res.status(400).send({ message: "Invalid user ID format" });
      }

      try {
        // Find the user by ObjectId
        const user = await userCollection.findOne({
          _id: new ObjectId(userId),
        });

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        // --- Security Check (Optional but Recommended) ---
        // Prevents a regular user from querying arbitrary user data,
        // unless they are Admin or the user profile they are requesting.
        const isAdmin = req.user.role === "admin";
        const isSelf = user.email === req.decoded_email;

        if (!isAdmin && !isSelf) {
          // Optional: You might allow Tutors to view Student profiles they interact with.
          // For now, restrict to Admin or Self.
          return res
            .status(403)
            .send({ message: "Forbidden access to other user's profile" });
        }

        res.send(user);
      } catch (err) {
        // This catch block handles internal server errors (e.g., DB connection issues)
        console.error("Error fetching user:", err);
        res.status(500).send({ message: "Failed to fetch user data" });
      }
    });

    // PATCH /users/:id: Update user info/role (Admin only)
    app.patch("/users/:id", verifyFBToken, async (req, res) => {
      try {
        const userId = req.params.id;
        const updatedDoc = req.body;

        // --- Authorization Check (Admin Only) ---
        if (req.user.role !== "admin") {
          return res
            .status(403)
            .send({ message: "Forbidden access: Requires Admin role" });
        }

        // Filter out non-editable fields
        const { _id, email, createdAt, ...fieldsToUpdate } = updatedDoc;

        const result = await userCollection.updateOne(
          { _id: new ObjectId(userId) },
          {
            $set: {
              ...fieldsToUpdate,
              updatedAt: new Date(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "User not found" });
        }

        res.send(result);
      } catch (err) {
        console.error("Error updating user:", err);
        if (err.name === "BSONTypeError") {
          return res.status(400).send({ message: "Invalid user ID format" });
        }
        res.status(500).send({ message: "Failed to update user information" });
      }
    });

    // DELETE /users/:id: Delete user (Admin only, includes Firebase delete)
    app.delete("/users/:id", verifyFBToken, async (req, res) => {
      try {
        const userId = req.params.id;

        if (req.user.role !== "admin") {
          return res
            .status(403)
            .send({ message: "Forbidden access: Requires Admin role" });
        }

        // ... (rest of the delete logic is good and remains) ...

        const userToDelete = await userCollection.findOne({
          _id: new ObjectId(userId),
        });

        if (!userToDelete) {
          return res
            .status(404)
            .send({ message: "User not found in database" });
        }

        try {
          const firebaseUser = await admin
            .auth()
            .getUserByEmail(userToDelete.email);
          await admin.auth().deleteUser(firebaseUser.uid);
          console.log(
            `Successfully deleted user from Firebase: ${userToDelete.email}`
          );
        } catch (firebaseErr) {
          if (firebaseErr.code !== "auth/user-not-found") {
            console.error("Error deleting user from Firebase:", firebaseErr);
          }
        }

        const result = await userCollection.deleteOne({
          _id: new ObjectId(userId),
        });

        if (result.deletedCount === 0) {
          return res
            .status(500)
            .send({ message: "Database deletion failed after Firebase step" });
        }

        res.send(result);
      } catch (err) {
        console.error("Error deleting user:", err);
        if (err.name === "BSONTypeError") {
          return res.status(400).send({ message: "Invalid user ID format" });
        }
        res.status(500).send({ message: "Failed to process user deletion" });
      }
    });

    // ===== Tuition Routes (Major Fixes Applied) =====

    // GET /tuitions: Fetch all (Admin) or by email (Student)
    app.get("/tuitions", verifyFBToken, async (req, res) => {
      try {
        const { email } = req.query;
        const userRole = req.user.role; // Safe to use now
        let query = {};

        if (email) {
          // User is fetching their own tuitions (requires email match)
          if (email !== req.decoded_email) {
            return res.status(403).send({ message: "Forbidden access" });
          }
          query = { email };
        } else if (userRole === "admin") {
          // Admin is fetching all tuitions (no filter)
          query = {};
        } else {
          // Public/Tutor view: Only allow approved/confirmed posts
          query = { status: { $in: ["approved", "confirmed"] } };
          // Optionally, you might want a separate, non-verified route for public viewing.
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

    // GET /tuitions/:id: Fetch single tuition (with access control)
    app.get("/tuitions/:id", verifyFBToken, async (req, res) => {
      const tuitionId = req.params.id;
      const userRole = req.user.role;
      const userEmail = req.user.email;

      try {
        if (!ObjectId.isValid(tuitionId)) {
          return res.status(400).send({ message: "Invalid tuition ID format" });
        }

        const tuition = await tuitionCollection.findOne({
          _id: new ObjectId(tuitionId),
        });

        if (!tuition) {
          return res.status(404).send({ message: "Tuition not found" });
        }

        // --- Access Control Logic ---
        const isCreator = tuition.email === userEmail; // Assuming email is stored as creator identifier
        const isApprovedOrConfirmed = ["approved", "confirmed"].includes(
          tuition.status
        );
        const isAdmin = userRole === "admin";

        if (isAdmin || isCreator || isApprovedOrConfirmed) {
          return res.send(tuition);
        } else {
          return res.status(403).send({
            message: "Access denied. Post is pending review or was rejected.",
          });
        }
      } catch (err) {
        console.error("Error fetching tuition:", err);
        res.status(500).send({ message: "Failed to fetch tuition" });
      }
    });

    // POST /tuitions: Create new tuition
    app.post("/tuitions", verifyFBToken, async (req, res) => {
      try {
        const tuition = req.body;
        // Add required fields upon creation
        tuition.createdAt = new Date();
        tuition.status = "pending"; // New posts start as pending
        tuition.email = req.decoded_email; // Enforce creator's email

        const result = await tuitionCollection.insertOne(tuition);
        res.send({ insertedId: result.insertedId });
      } catch (err) {
        console.error("Error creating tuition:", err);
        res.status(500).send({ message: "Failed to create tuition" });
      }
    });

    // PATCH /tuitions/:id: Update tuition (Admin status change or Student edit)
    app.patch("/tuitions/:id", verifyFBToken, async (req, res) => {
      const tuitionId = req.params.id;
      const { status, ...updatedDoc } = req.body;
      const userRole = req.user.role;
      const userEmail = req.user.email;

      try {
        const existingTuition = await tuitionCollection.findOne({
          _id: new ObjectId(tuitionId),
        });
        if (!existingTuition) {
          return res.status(404).send({ message: "Tuition not found" });
        }

        let updateFields = {
          ...updatedDoc,
          updatedAt: new Date().toISOString(),
        };

        // --- Authorization and Status Logic ---
        if (userRole === "admin") {
          const validAdminStatuses = ["approved", "rejected"];
          if (validAdminStatuses.includes(status)) {
            updateFields.status = status;
          } else if (status) {
            return res
              .status(400)
              .send({ message: "Admin provided an invalid status." });
          }
          // If admin is updating other fields, they are just updated without changing status unless specified.
        } else if (existingTuition.email === userEmail) {
          // Student/Creator is editing the post content
          // The post must go back to pending for re-approval
          updateFields.status = "pending";
          // Ensure the creator cannot overwrite the 'email' or 'createdAt' fields
          delete updateFields.email;
          delete updateFields.createdAt;
        } else {
          return res.status(403).send({
            message: "Forbidden access: Not authorized to update this post.",
          });
        }

        const result = await tuitionCollection.updateOne(
          { _id: new ObjectId(tuitionId) },
          { $set: updateFields }
        );

        res.send(result);
      } catch (err) {
        console.error("Error updating tuition:", err);
        res.status(500).send({ message: "Failed to update tuition" });
      }
    });

    // DELETE /tuitions/:id: Delete tuition (Creator or Admin)
    app.delete("/tuitions/:id", verifyFBToken, async (req, res) => {
      const tuitionId = req.params.id;
      const userRole = req.user.role;
      const userEmail = req.user.email;

      try {
        const existingTuition = await tuitionCollection.findOne({
          _id: new ObjectId(tuitionId),
        });

        if (!existingTuition) {
          return res.status(404).send({ message: "Tuition not found" });
        }

        // --- Authorization Check ---
        if (existingTuition.email !== userEmail && userRole !== "admin") {
          return res.status(403).send({
            message: "Forbidden: You are not authorized to delete this post.",
          });
        }

        const result = await tuitionCollection.deleteOne({
          _id: new ObjectId(tuitionId),
        });

        if (result.deletedCount === 0) {
          return res
            .status(500)
            .send({ message: "Deletion failed in database." });
        }

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
