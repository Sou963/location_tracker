const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const { MongoClient } = require("mongodb");
const auth = require("./auth");

const app = express();

// ===== MongoDB connection (CACHED) =====
const uri = process.env.MONGODB_URI;
let cachedClient = null;

async function getDB() {
  if (!cachedClient) {
    const client = new MongoClient(uri);
    cachedClient = await client.connect();
    console.log("✅ MongoDB Connected");
  }
  return cachedClient.db("user_info");
}

// ===== Middleware =====
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));

// ===== Pages =====
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/login.html"));
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/reg.html"));
});

app.get("/mytracker", (req, res) => {
  res.sendFile(path.join(__dirname, "../views/track.html"));
});

// ===== Register =====
app.post("/register", async (req, res) => {
  try {
    const db = await getDB();
    const col = db.collection("information");

    const { name, email, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
      return res.send("Password not matching");
    }

    const exists = await col.findOne({ email });
    if (exists) {
      return res.send("Email already exists");
    }

    const hash = await bcrypt.hash(password, 10);
    await col.insertOne({ name, email, password: hash });

    res.sendFile(path.join(__dirname, "../views/login.html"));
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

// ===== Login =====
app.post("/login", async (req, res) => {
  try {
    const db = await getDB();
    const col = db.collection("information");

    const { email, password } = req.body;
    const user = await col.findOne({ email });

    if (!user) return res.send("Invalid email or password");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.send("Invalid email or password");

    res.sendFile(path.join(__dirname, "../views/share.html"));
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});

// ===== OAuth routes =====
app.use(auth);

module.exports = app;
