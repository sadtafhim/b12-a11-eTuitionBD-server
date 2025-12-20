const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

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

app.use(cors());
app.use(express.json());

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
let applicationCollection;
let paymentCollection;

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

    req.decoded_email = decoded.email.toLowerCase();

    const userEmail = decoded.email.toLowerCase();
    const user = await userCollection.findOne({ email: userEmail });

    if (!user) {
      return res
        .status(403)
        .send({ message: "Forbidden: User record missing." });
    }

    req.user = user;
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
    applicationCollection = db.collection("applications");
    paymentCollection = db.collection("payments");

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
          res.send(users[0] || {});
        } else {
          res.send(users);
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

        // Strict Admin check
        if (req.user.role !== "admin") {
          return res.status(403).send({ message: "Forbidden: Admin Only" });
        }

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
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: "Admin update failed" });
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

    app.patch("/users/profile/update", verifyFBToken, async (req, res) => {
      try {
        const requester = req.user;
        const { displayName, email, photoURL } = req.body;

        const filter = { _id: new ObjectId(requester._id) };
        const updateDoc = {
          $set: {
            displayName,
            email: email.toLowerCase(),
            photoURL,
            updatedAt: new Date(),
          },
        };

        const result = await userCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: "Failed to update profile" });
      }
    });

    // ===== Tuition Routes (Major Fixes Applied) =====

    // GET /tuitions: Fetch all (Admin) or by email (Student)
    app.get("/tuitions", verifyFBToken, async (req, res) => {
      try {
        const { email, page, size } = req.query;
        const decodedEmail = req.decoded_email;
        const userRole = req.user?.role;

        let query = {};

        if (userRole === "admin") {
          query = {};
        } else if (email) {
          if (email !== decodedEmail) {
            return res.status(403).send({ message: "Forbidden access" });
          }
          query = { email: email };
        } else {
          query = {
            status: { $in: ["approved", "applied", "confirmed"] },
          };
        }

        const pageNum = parseInt(page) || 0;
        const limitNum = parseInt(size) || 6;

        const totalCount = await tuitionCollection.countDocuments(query);
        const result = await tuitionCollection
          .find(query)
          .skip(pageNum * limitNum)
          .limit(limitNum)
          .sort({ createdAt: -1 })
          .toArray();

        const userApplications = await applicationCollection
          .find({ tutorEmail: decodedEmail })
          .project({ tuitionId: 1 })
          .toArray();

        const appliedIds = new Set(
          userApplications.map((app) => app.tuitionId.toString())
        );

        const finalData = result.map((t) => ({
          ...t,
          hasApplied: appliedIds.has(t._id.toString()),
        }));

        res.send({ result: finalData, totalCount });
      } catch (err) {
        res.status(500).send({ message: "Internal Server Error" });
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

    // GET /tutor-ongoing-tuitions -> Fetch only "accepted" tuitions for the logged-in tutor
    app.get("/tutor-ongoing-tuitions", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const query = { tutorEmail: email, status: "accepted" };

        const result = await applicationCollection
          .find(query)
          .sort({ acceptedAt: -1 })
          .toArray();

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch ongoing tuitions" });
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

    // ===== Application Routes =====

    app.post("/applications", verifyFBToken, async (req, res) => {
      try {
        const application = req.body;
        application.tutorEmail = req.decoded_email;

        const result = await applicationCollection.insertOne(application);
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: "Server error" });
      }
    });
    // GET /application/:id -> Fetch applications for a tutor by email
    app.get("/application/:id", verifyFBToken, async (req, res) => {
      try {
        const tutorEmailFromParams = req.params.id;
        const decodedEmail = req.decoded_email;
        if (tutorEmailFromParams !== decodedEmail) {
          return res.status(403).send({ message: "Forbidden Access" });
        }

        const query = { tutorEmail: tutorEmailFromParams };
        const result = await applicationCollection
          .find(query)
          .sort({ appliedAt: -1 })
          .toArray();

        res.send(result);
      } catch (error) {
        console.error("Error fetching applications:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    });
    app.patch("/applications/reject/:id", verifyFBToken, async (req, res) => {
      const appId = req.params.id;
      const studentEmail = req.decoded_email;

      try {
        const query = { _id: new ObjectId(appId), studentEmail: studentEmail };
        const result = await applicationCollection.updateOne(query, {
          $set: { status: "rejected" },
        });

        if (result.modifiedCount === 0) {
          return res
            .status(404)
            .send({ message: "Application not found or unauthorized" });
        }
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: "Error rejecting application" });
      }
    });
    app.get(
      "/tuition-applications/:tuitionId",
      verifyFBToken,
      async (req, res) => {
        const { tuitionId } = req.params;
        const query = { tuitionId: tuitionId };
        const result = await applicationCollection.find(query).toArray();
        res.send(result);
      }
    );

    // ===== Payment Routes =====
    app.post("/payments", verifyFBToken, async (req, res) => {
      const paymentInfo = req.body;
      try {
        const paymentResult = await paymentCollection.insertOne({
          ...paymentInfo,
          date: new Date(),
          paymentStatus: "paid",
        });

        await applicationCollection.updateOne(
          { _id: new ObjectId(paymentInfo.applicationId) },
          { $set: { status: "accepted" } }
        );

        await applicationCollection.updateMany(
          {
            tuitionId: paymentInfo.tuitionId,
            _id: { $ne: new ObjectId(paymentInfo.applicationId) },
          },
          { $set: { status: "rejected" } }
        );

        await tuitionCollection.updateOne(
          { _id: new ObjectId(paymentInfo.tuitionId) },
          { $set: { status: "confirmed" } }
        );

        res.send({ success: true, paymentResult });
      } catch (err) {
        console.error("Hiring workflow error:", err);
        res
          .status(500)
          .send({ message: "Failed to complete the hiring process" });
      }
    });

    app.post("/create-payment-intent", verifyFBToken, async (req, res) => {
      const { salary } = req.body;
      if (!salary)
        return res.status(400).send({ message: "Salary is required" });

      const amount = Math.round(parseFloat(salary) * 100); // Stripe needs cents

      try {
        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount,
          currency: "usd",
          payment_method_types: ["card"],
        });
        res.send({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });
    app.get("/payments/history", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const query = { studentEmail: email };

        const result = await paymentCollection
          .find(query)
          .sort({ date: -1 }) // Newest payments first
          .toArray();

        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to fetch payment history" });
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
