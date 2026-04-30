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
  .then(async () => {
    console.log("MongoDB Connected");
	
	await User.updateOne(
	  { username: "nani7984" },
	  { $set: { role: "admin" } }
	);
  })
  .catch(err => console.log(err));
 
 

console.log("Admin role assigned");

/* =========================
   📦 USER MODEL
========================= */
const UserSchema = new mongoose.Schema({
  fullName: String,
  gender: String,
  email: { type: String, unique: true, sparse: true },
  phone: String,
  country: String,

  username: { type: String, unique: true },
  password: String,
  accounts: [String],

  otp: String,
  otpExpiry: Date,

  verified: { type: Boolean, default: false },

  // 🔥 ADD THIS
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user"
  }
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
    const {
      fullName,
      gender,
      email,
      phone,
      country,
      username,
      password
    } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username & Password required ❌" });
    }

    if (!fullName || !email || !phone) {
      return res.status(400).json({ error: "All details required ❌" });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: "Username already exists ❌" });
    }

    if (email) {
      const existingEmail = await User.findOne({ email });
      if (existingEmail) {
        return res.status(400).json({ error: "Email already registered ❌" });
      }
    }

    const hashed = await bcrypt.hash(password, 10);

    // ✅ NEW LOGIC
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await User.create({
      fullName,
      gender,
      email,
      phone,
      country,
      username,
      password: hashed,
      accounts: [],

      otp: otp,
      otpExpiry: Date.now() + 5 * 60 * 1000,
      verified: false
    });

    console.log("REGISTER OTP:", otp);

    res.json({ message: "OTP sent for verification" });

  } catch (err) {
    console.log("REGISTER ERROR:", err);
    res.status(500).json({ error: "Server error ❌" });
  }
});

app.post("/api/verify-register", async (req, res) => {
  try {
    const { username, otp } = req.body;

    if (!username || !otp) {
      return res.status(400).json({ error: "Missing data ❌" });
    }

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ error: "User not found ❌" });
    }

    // ❌ Already verified
    if (user.verified) {
      return res.json({ message: "Already verified ✅" });
    }

    // ❌ Wrong or expired OTP
    if (user.otp !== otp || Date.now() > user.otpExpiry) {
      return res.status(400).json({ error: "Invalid or expired OTP ❌" });
    }

    // ✅ SUCCESS
    user.verified = true;
    user.otp = null;
    user.otpExpiry = null;

    await user.save();

    res.json({ message: "Account verified successfully ✅" });

  } catch (err) {
    console.log("VERIFY ERROR:", err);
    res.status(500).json({ error: "Server error ❌" });
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

  // ❌ BLOCK if not verified
  if (!user.verified) {
    return res.status(403).json({ error: "Please verify your account first ❌" });
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).json({ error: "Wrong password" });
  }

  // ✅ ADD ROLE IN TOKEN
  const token = jwt.sign(
    { id: user._id, role: user.role || "user" },
    SECRET,
    { expiresIn: "1d" }
  );

  // ✅ SEND ROLE TO FRONTEND
  res.json({
    token,
    userId: user._id,
    role: user.role || "user"
  });
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
  
  // ✅ VALIDATION
  if (!isValidAccount(account)) {
    return res.status(400).json({
      error: "Account must be exactly 9 digits (numbers only)"
    });
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
   📊 update-account
========================= */

app.post("/api/update-account", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { oldAccount, newAccount } = req.body;

    if (!oldAccount || !newAccount) {
      return res.status(400).json({ error: "Missing fields" });
    }
	
	if (!isValidAccount(newAccount)) {
	  return res.status(400).json({
		error: "Account must be exactly 9 digits (numbers only)"
	  });
	}

    const user = await User.findById(userId);

    if (!user.accounts.includes(oldAccount)) {
      return res.status(400).json({ error: "Old account not found" });
    }

    // ❌ Prevent duplicate across users
    const existing = await User.findOne({ accounts: newAccount });
    if (existing) {
      return res.status(400).json({ error: "Account already used" });
    }

    // ✅ Replace account
    user.accounts = user.accounts.map(acc =>
      acc === oldAccount ? newAccount : acc
    );

    await user.save();

    // ✅ Also update Data collection
    await Data.updateMany(
      { account: oldAccount },
      { account: newAccount }
    );

    res.json({ message: "Account updated successfully" });

  } catch (err) {
    console.log("UPDATE ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* =========================
   ✏️ UPDATE PROFILE
========================= */
app.post("/api/update-profile", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { fullName, gender, email } = req.body;

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // ✅ Update fields
    user.fullName = fullName || user.fullName;
    user.gender = gender || user.gender;
    user.email = email || user.email;

    await user.save();

    res.json({
      message: "Profile updated ✅",
      user: {
        fullName: user.fullName,
        gender: user.gender,
        email: user.email,
        username: user.username
      }
    });

  } catch (err) {
    console.log("UPDATE PROFILE ERROR:", err);
    res.status(500).json({ error: "Server error ❌" });
  }
});

/* =========================
   🔐 CHANGE PASSWORD
========================= */
app.post("/api/change-password", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({
        error: "All fields required ❌"
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters ❌"
      });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found ❌" });
    }

    // ✅ Check old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (!isMatch) {
      return res.status(400).json({
        error: "Old password is incorrect ❌"
      });
    }

    // ✅ Hash new password
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;

    await user.save();

    res.json({ message: "Password changed successfully ✅" });

  } catch (err) {
    console.log("CHANGE PASSWORD ERROR:", err);
    res.status(500).json({
      error: "Server error ❌",
      details: err.message
    });
  }
});

/* =========================
   📊 Delete-account
========================= */

app.post("/api/delete-account", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { account } = req.body;

    const user = await User.findById(userId);

    if (!user.accounts.includes(account)) {
      return res.status(400).json({ error: "Account not found" });
    }

    // ✅ Remove from user only
    user.accounts = user.accounts.filter(acc => acc !== account);
    await user.save();

    // ✅ Optional: remove its data (recommended)
    await Data.deleteOne({ account });

    res.json({ message: "Account removed" });

  } catch (err) {
    console.log("DELETE ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
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
	  fullName: user.fullName,
	  gender: user.gender,
	  email: user.email,
	  phone: user.phone,
	  country: user.country,
	  accounts: result
	});
	
  });

/* =========================
   📌 COMMAND API
========================= */
let lastCommand = {};

app.post("/api/send-command", auth, (req, res) => {
  const { command, account, ticket } = req.body;

  if (!account || !command) {
    return res.status(400).json({ error: "Missing data" });
  }

  lastCommand[account] = {
    command,
    account,
    ticket: ticket || null, // 🔥 NEW
    time: Date.now(),
    executed: false
  };

  console.log("QUEUED:", lastCommand[account]);

  res.json({ success: true });
});

app.get("/api/command", (req, res) => {
  const account = req.query.account;

  if (!account) {
    return res.json({ command: "NONE" });
  }

  const cmd = lastCommand[account];

  if (!cmd) {
    return res.json({ command: "NONE" });
  }

  // ⏱ allow command for 5 seconds
  const age = Date.now() - cmd.time;

  if (age > 5000) {
    delete lastCommand[account];
    return res.json({ command: "NONE" });
  }

  res.json(cmd);
});

function isValidAccount(account) {
  return /^[0-9]{9}$/.test(account); // ✅ exactly 9 digits only
}

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