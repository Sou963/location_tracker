const express = require("express");
const passport = require("passport");
const session = require("express-session");
const path = require("path");
const { MongoClient } = require("mongodb");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;

const auth = express();

// MongoDB setup

const client = new MongoClient(process.env.MONGODB_URI);
const dbName = "user_info";
let usersCollection;

async function connectDB() {
  try {
    await client.connect();
    usersCollection = client.db(dbName).collection("information");
    console.log("✅ MongoDB Connected");
  } catch (err) {
    console.error(err);
  }
}
connectDB();

// Express session
auth.use(
  session({
    secret: "yourSecretKey",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 1 day
  })
);

auth.use(passport.initialize());
auth.use(passport.session());

// Serialize/Deserialize
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Save user to MongoDB
async function saveUser(profile, provider) {
  const existingUser = await usersCollection.findOne({
    provider_id: profile.id,
  });
  if (!existingUser) {
    await usersCollection.insertOne({
      name: profile.displayName,
      email: profile.emails?.[0]?.value || "No Email",
      provider,
      provider_id: profile.id,
      createdAt: new Date(),
    });
    console.log(`✅ New user added from ${provider}`);
  }
  return {
    id: profile.id,
    displayName: profile.displayName,
    email: profile.emails?.[0]?.value || "No Email",
  };
}

// Strategy callback wrapper
function strategyCallback(provider) {
  return async (accessToken, refreshToken, profile, done) => {
    try {
      const user = await saveUser(profile, provider);
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  };
}

// Passport Strategies

// Google
passport.use(
  new GoogleStrategy(
    {
      clientID: "",
      clientSecret: "",
      callbackURL: "/auth/google/callback",
    },
    strategyCallback("google")
  )
);

// Facebook
passport.use(
  new FacebookStrategy(
    {
      clientID: "",
      clientSecret: "",
      callbackURL: "/auth/facebook/callback",
      profileFields: ["id", "displayName", "emails"],
    },
    strategyCallback("facebook")
  )
);

// GitHub
passport.use(
  new GitHubStrategy(
    {
      clientID: "YOUR_GITHUB_CLIENT_ID",
      clientSecret: "YOUR_GITHUB_CLIENT_SECRET",
      callbackURL: "/auth/github/callback",
    },
    strategyCallback("github")
  )
);

//  success.html

//Routes

// Google
auth.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
auth.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => res.sendFile(path.join(__dirname, "/views/share.html"))
);

// Facebook
auth.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);
auth.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/" }),
  (req, res) => res.sendFile(path.join(__dirname, "/views/share.html"))
);

// GitHub
auth.get(
  "/auth/github",
  passport.authenticate("github", { scope: ["user:email"] })
);
auth.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/" }),
  (req, res) => res.sendFile(successPath)
);

module.exports = auth;
