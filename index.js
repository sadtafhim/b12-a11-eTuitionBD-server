const express = require("express");
var cors = require("cors");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 3000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const admin = require("firebase-admin");

const serviceAccount = require("./e-tuition-bd-firebase-adminsdk.json");

admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.FIREBASE_TYPE,
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
  }),
});

app.use(cors());
app.use(express.json());

const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }

  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    console.log("decoded in the token", decoded);
    req.decoded_email = decoded.email;
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  next();
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.h1ahmwn.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const db = client.db("eTuitionBD_db");
    const tuitionCollection = db.collection("tuitions");

    app.get("/tuitions", verifyFBToken, async (req, res) => {
      const query = {};
      const { email } = req.query;

      if (email) {
        query.email = email;

        if (email !== req.decoded_email) {
          return res.status(403).send({ message: "forbidden access" });
        }
      }

      const options = { sort: { createdAt: -1 } };

      const cursor = tuitionCollection.find(query, options);
      const result = await cursor.toArray();
      res.send(result);

      console.log("headers", req.headers);
    });

    app.post("/tuitions", async (req, res) => {
      const tuition = req.body;
      const result = await tuitionCollection.insertOne(tuition);
      res.send(result);
    });

    app.get("/tuitions/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await tuitionCollection.findOne(query);
        res.send(result);
      } catch (error) {
        console.error("Error fetching single tuition:", error);
        res.status(404).send({ message: "Tuition not found or invalid ID." });
      }
    });
    app.delete("/tuitions/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };

      const result = await tuitionCollection.deleteOne(query);
      res.send(result);
    });

    app.patch("/tuitions/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const updatedDoc = req.body;

        const query = { _id: new ObjectId(id) };

        // Only include updatable fields and metadata.
        // **FIX: Removed _id: undefined**
        const updateOperation = {
          $set: {
            ...updatedDoc,
            status: "pending",
            updatedAt: new Date().toISOString(),
          },
        };

        const result = await tuitionCollection.updateOne(
          query,
          updateOperation,
          { upsert: false }
        );

        res.send(result);
      } catch (error) {
        // Catches the error to prevent the server from crashing
        console.error("Error updating tuition:", error);
        res
          .status(500)
          .send({ message: "Failed to update tuition due to a server error." });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("eTutionBD Server is Running!");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
