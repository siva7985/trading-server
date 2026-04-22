const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = "my_secret_key";

/* =========================
   🔗 MONGODB CONNECT
========================= */
mongoose.connect("mongodb+srv://admin:Nsrk798489@tradingapp.t6uqbxa.mongodb.net/trading_app?retryWrites=true&w=majority")
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

/* =========================
   📦 USER MODEL
========================= */
const UserSchema = new mongoose.Schema({
  username: String,
  password: String
});

const User = mongoose.model("User", UserSchema);

/* =========================
   🔐 REGISTER (for testing)
========================= */
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  await User.create({
    username,
    password: hashed
  });

  res.json({ message: "User created" });
});

app.get("/reset-user", async (req, res) => {
  await User.deleteMany({});
  res.send("All users deleted");
});

/* =========================
   🔐 LOGIN
========================= */
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });

  if (!user) {
    return res.status(401).json({ error: "User not found" });
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).json({ error: "Wrong password" });
  }

  const token = jwt.sign({ id: user._id }, SECRET, {
    expiresIn: "1d"
  });

  res.json({ token });
});

/* =========================
   🔐 AUTH MIDDLEWARE
========================= */
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) return res.status(403).send("No token");

  const token = header.split(" ")[1];

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).send("Invalid token");

    req.user = user;
    next();
  });
}

/* =========================
   📌 COMMAND API
========================= */
let command = "";

app.post("/api/send-command", auth, (req, res) => {
  command = req.body.command;
  console.log("CMD:", command);
  res.send("OK");
});

app.get("/api/command", (req, res) => {
  const temp = command;
  command = "";
  res.send(temp || "");
});

/* =========================
   📊 DATA API
========================= */
let latestData = {};

app.post("/api/update", (req, res) => {
  latestData = req.body;
  res.send("OK");
});

app.get("/api/data", (req, res) => {
  res.json(latestData);
});

/* =========================
   🚀 START SERVER
========================= */
app.listen(3000, () => {
  console.log("Server running on port 3000");
});