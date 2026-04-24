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
  username: { type: String, unique: true },
  password: String,
  accounts: [String],   // ✅ MULTIPLE ACCOUNTS
  otp: String,
  otpExpiry: Date
});

const User = mongoose.model("User", UserSchema);

/* =========================
   📦 DATA MODEL (FIXED)
========================= */
const DataSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  account: {
    type: String,
    required: true
  },
  balance: Number,
  equity: Number,
  profit: Number,
  trades: Array
});

// 🔥 IMPORTANT (multi-account per user)
DataSchema.index({ userId: 1, account: 1 }, { unique: true });

const Data = mongoose.model("Data", DataSchema);

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
   🔐 REGISTER
========================= */
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(400).json({ error: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await User.create({
      username,
      password: hashed,
      accounts: []   // ✅ correct
    });

    res.json({ message: "User created" });

  } catch (err) {
    console.log("REGISTER ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
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

  res.json({ token, userId: user._id });
});

/* =========================
   ➕ ADD ACCOUNT
========================= */
app.post("/api/add-account", auth, async (req, res) => {
  const userId = req.user.id;
  const { account } = req.body;

  if (!account) {
    return res.status(400).json({ error: "Account required" });
  }

  const user = await User.findById(userId);

  if (user.accounts.includes(account)) {
    return res.status(400).json({ error: "Already added" });
  }

  // ❗ Prevent same account in multiple users
  const existing = await User.findOne({ accounts: account });
  if (existing) {
    return res.status(400).json({ error: "Account already used by another user" });
  }

  user.accounts.push(account);
  await user.save();

  res.json({ message: "Account added successfully" });
});

/* =========================
   🔐 FORGOT PASSWORD
========================= */
app.post("/api/forgot-password", async (req, res) => {
  const { username } = req.body;

  const user = await User.findOne({ username });

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  user.otp = otp;
  user.otpExpiry = Date.now() + 5 * 60 * 1000;

  await user.save();

  console.log("OTP:", otp);

  res.json({ message: "OTP sent" });
});

/* =========================
   🔐 RESET PASSWORD
========================= */
app.post("/api/reset-password", async (req, res) => {
  const { username, otp, newPassword } = req.body;

  const user = await User.findOne({ username });

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  if (user.otp !== otp || Date.now() > user.otpExpiry) {
    return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  const hashed = await bcrypt.hash(newPassword, 10);

  user.password = hashed;
  user.otp = null;
  user.otpExpiry = null;

  await user.save();

  res.json({ message: "Password reset successful" });
});

/* =========================
   📊 EA DATA UPDATE
========================= */
app.post("/api/update", async (req, res) => {
  const { account, balance, equity, profit, trades } = req.body;

  const user = await User.findOne({ accounts: account });

  if (!user) {
    return res.status(403).send("Account not linked");
  }

  await Data.findOneAndUpdate(
  { userId: user._id, account },  // 🔥 THIS IS KEY
  {
    userId: user._id,
    account,
    balance,
    equity,
    profit,
    trades
  },
  { upsert: true, new: true }
);

  res.send("OK");
});

/* =========================
   📊 FETCH USER DATA
========================= */
app.get("/api/data", auth, async (req, res) => {
  const userId = req.user.id;

  const user = await User.findById(userId);

  const data = await Data.find({
    account: { $in: user.accounts }
  });

  const result = user.accounts.map(acc => {
    const d = data.find(x => x.account === acc);

    return {
      account: acc,
      balance: d?.balance || null,
      equity: d?.equity || null,
      profit: d?.profit || null,
      trades: d?.trades || []
    };
  });

  res.json({
    username: user.username,
    accounts: result
  });
});

/* =========================
   📌 COMMAND API
========================= */
let commands = {}; // user-wise

app.post("/api/send-command", auth, (req, res) => {
  const userId = req.user.id;
  const { account, command } = req.body;

  if (!commands[userId]) commands[userId] = {};

  commands[userId][account] = command;

  io.to(userId).emit("command", { account, command });

  res.send("OK");
});

app.get("/api/command", (req, res) => {
  const temp = command;
  command = "";
  res.send(temp || "");
});

/* =========================
   ROOT
========================= */
app.get("/", (req, res) => {
  res.send("Server running ✅");
});

/* =========================
   🚀 START SERVER
========================= */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});

app.get("/debug-data", async (req, res) => {
  try {
    const all = await Data.find();
    res.json(all);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});