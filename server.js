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
  mt5Account: String,
  otp: String,
  otpExpiry: Date
});

const User = mongoose.model("User", UserSchema);

/* =========================
   📦 DATA MODEL
========================= */

const DataSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  account: String,
  balance: Number,
  equity: Number,
  profit: Number,
  trades: Array
});

const Data = mongoose.model("Data", DataSchema);

/* =========================
   🔐 REGISTER (for testing)
========================= */
app.post("/api/register", async (req, res) => {
  const { username, password, mt5Account } = req.body;

  if (!mt5Account) {
    return res.status(400).json({ error: "MT5 Account required" });
  }

  const existing = await User.findOne({ username });
  if (existing) {
    return res.status(400).json({ error: "User already exists" });
  }

  const hashed = await bcrypt.hash(password, 10);

  await User.create({
    username,
    password: hashed,
    mt5Account
  });

  res.json({ message: "User created" });
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
   🔐 Forget Password
========================= */

app.post("/api/forgot-password", async (req, res) => {
  const { username } = req.body;

  const user = await User.findOne({ username });

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  // Generate 6 digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  user.otp = otp;
  user.otpExpiry = Date.now() + 5 * 60 * 1000; // 5 mins

  await user.save();

  console.log("OTP:", otp); // 🔥 for testing (later send email)

  res.json({ message: "OTP sent" });
});

/* =========================
   🔐 Reset Password
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
   🔐 User update
========================= */

app.post("/api/update-account", auth, async (req, res) => {
  const userId = req.user.id;
  const { mt5Account } = req.body;

  if (!mt5Account) {
    return res.status(400).json({ error: "Account required" });
  }

  await User.findByIdAndUpdate(userId, {
    mt5Account: mt5Account
  });
  
  res.json({ message: "Account updated successfully" });
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

app.get("/", (req, res) => {
  res.send("Server is running ✅");
});

/* =========================
   📊 DATA API
========================= */

app.post("/api/update", async (req, res) => {
  const { account, balance, equity, profit, trades } = req.body;

  const user = await User.findOne({ mt5Account: account });

	if (!user) {
	  return res.status(403).send("Account not linked to any user");
	}

  await Data.findOneAndUpdate(
    { userId: user._id },
    { userId: user._id, account, balance, equity, profit, trades },
    { upsert: true }
  );
  
  //console.log("UPDATE BODY:", req.body);

  res.send("OK");
});

app.get("/api/data", auth, async (req, res) => {
  const userId = req.user.id;

  const user = await User.findById(userId);
  const data = await Data.findOne({ userId });

  const isValidAccount =
    data &&
    String(user.mt5Account).trim() === String(data.account).trim();

  res.json({
    username: user?.username,
    account: user?.mt5Account,
	
	dataReceived: !!data,
	
    accountValid: isValidAccount,
    balance: isValidAccount ? data?.balance : null,
    equity: isValidAccount ? data?.equity : null,
    profit: isValidAccount ? data?.profit : null,
    trades: isValidAccount ? data?.trades : []
  });
  
  console.log("USER:", user.mt5Account);
  console.log("EA:", data?.account);
});

app.get("/cleanup", async (req, res) => {
  const result = await Data.deleteMany({
    $or: [
      { userId: { $exists: false } },
      { account: { $exists: false } }
    ]
  });

  res.json({ deleted: result.deletedCount });
});

/* =========================
   🚀 START SERVER
========================= */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});