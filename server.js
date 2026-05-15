const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());

const otpStore = {};

app.use(cors({
  origin: "*",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

const SECRET = "my_secret_key";

/* =========================
   🔗 MONGODB CONNECT
========================= */
mongoose.connect(
  "mongodb://admin:Nsrk798489@ac-qzlcbod-shard-00-00.t6uqbxa.mongodb.net:27017,ac-qzlcbod-shard-00-01.t6uqbxa.mongodb.net:27017,ac-qzlcbod-shard-00-02.t6uqbxa.mongodb.net:27017/trading_app?ssl=true&replicaSet=atlas-esm0ag-shard-0&authSource=admin&appName=TradingApp"
)
.then(() => {
  console.log("MongoDB Connected ✅");
})
.catch(err => {
  console.log("MongoDB ERROR ❌");
  console.log(err);
});

/* =========================
   📦 USER MODEL
========================= */
const UserSchema = new mongoose.Schema({
  fullName: String,
  gender: String,
  email: { type: String},
  phone: String,
  country: String,

  username: { type: String},
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
  },

	isActive: {
	  type: Boolean,
	  default: true
	},	
	
	suspendReason: {
	  type: String,
	  default: ""
	},
	suspendedAt: Date,
	suspendedBy: String,
	
	forcePasswordChange: {
	  type: Boolean,
	  default: false,
	},
});

const User = mongoose.model("User", UserSchema);


app.get("/check-users", async (req, res) => {
  const users = await User.find();

  console.log(users);

  res.json(users);
});

app.get("/debug-register", async (req, res) => {

  const users = await User.find();

  const emails = users.map(u => u.email);
  const usernames = users.map(u => u.username);

  res.json({
    emails,
    usernames
  });
});

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

  trades: Array,

  eaRunning: {
    type: Boolean,
    default: false
  },

  mt5Connected: {
    type: Boolean,
    default: false
  },

  vpsOnline: {
    type: Boolean,
    default: false
  },

  lastUpdate: {
    type: Date,
    default: Date.now
  },

  ping: {
    type: Number,
    default: 0
  }

});

// 🔥 IMPORTANT (multi-account per user)
DataSchema.index({ userId: 1, account: 1 }, { unique: true });

const Data = mongoose.model("Data", DataSchema);

/* =========================
   🔐 AUTH MIDDLEWARE
========================= */
async function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) return res.status(403).send("No token");

  const token = header.split(" ")[1];

  jwt.verify(token, SECRET, async (err, decoded) => {
    if (err) return res.status(403).send("Invalid token");

    const user = await User.findById(decoded.id);

    // 🔥 AUTO BLOCK
    if (!user || !user.isActive) {
      return res.status(403).json({
        error: "Account suspended",
        code: "SUSPENDED"
      });
    }

    req.user = decoded;
    next();
  });
}

/* =========================
   🔐 ADMIN 
========================= */

/* =========================
   👤 ADMIN → SINGLE USER
========================= */
app.get("/api/admin/user/:userId", auth, async (req, res) => {
  try {
    // 🔒 Only admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied" });
    }

    const { userId } = req.params;

    const user = await User.findById(userId).select("-password");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);

  } catch (err) {
    console.log("FETCH USER ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/users", auth, async (req, res) => {

  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  const users = await User.find({ role: "user" });

  res.json(users);
});

app.post("/api/admin/delete-user", auth, async (req, res) => {

  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  const { userId } = req.body;

  await User.findByIdAndDelete(userId);

  res.json({ success: true });
});

app.get("/api/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

/* =========================
   📊 ADMIN → USER TRADES
========================= */

app.get("/api/admin/user-data/:userId", auth, async (req, res) => {

  // 🔒 Only admin allowed
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  const { userId } = req.params;

  const user = await User.findById(userId);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const data = await Data.find({
    account: { $in: user.accounts }
  });

  const result = user.accounts.map(acc => {
    const d = data.find(x => x.account === acc);

    return {
	  userId: user._id,
      account: acc,
      balance: d?.balance || 0,
      equity: d?.equity || 0,
      profit: d?.profit || 0,
      trades: d?.trades || []
    };
  });

  res.json({
    username: user.username,
    accounts: result
  });
});

app.post("/api/admin/toggle-user", auth, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Access denied ❌" });
    }

    const { userId, reason } = req.body;

    if (req.user.id === userId) {
      return res.status(400).json({
        error: "You cannot disable yourself ❌"
      });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // 🔥 TOGGLE
    user.isActive = !user.isActive;

    if (!user.isActive) {
      user.suspendReason = reason || "No reason provided";
      user.suspendedAt = new Date();
      user.suspendedBy = req.user.id;
    } else {
      user.suspendReason = "";
      user.suspendedAt = null;
      user.suspendedBy = null;
    }

    await user.save();

    res.json({
      success: true,
      isActive: user.isActive
    });
	
	await Audit.create({
	  adminId: req.user.id,
	  action: user.isActive ? "ACTIVATED" : "SUSPENDED",
	  targetUserId: user._id,
	  reason: user.suspendReason
	});

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

const AuditSchema = new mongoose.Schema({
  adminId: String,
  action: String,
  targetUserId: String,
  reason: String,
  time: { type: Date, default: Date.now }
});

const Audit = mongoose.model("Audit", AuditSchema);

app.get("/api/admin/audit", auth, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  const logs = await Audit.find().sort({ time: -1 });

  res.json(logs);
});

/* =========================
   🔐 REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  try {

    let {
      fullName,
      gender,
      email,
      phone,
      country,
      username,
      password
    } = req.body;

    email = email?.toLowerCase().trim();
    username = username?.trim();

    if (!fullName || !email || !username || !password) {
      return res.status(400).json({
        error: "All fields required ❌"
      });
    }

    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.status(400).json({
        error: "Username already exists ❌"
      });
    }

    const existingEmail = await User.findOne({ email });

    if (existingEmail) {
      return res.status(400).json({
        error: "Email already registered ❌"
      });
    }

    const hashed = await bcrypt.hash(password, 10);

    await User.create({
      fullName,
      gender,
      email,
      phone,
      country,
      username,
      password: hashed,
      accounts: [],
      role: "user",
      isActive: true
    });

    res.json({
      success: true,
      message: "Registration successful ✅"
    });

  } catch (err) {

    console.log("REGISTER ERROR:", err);

    res.status(500).json({
      error: "Server error ❌"
    });
  }
});

/* =========================
   🔐 LOGIN
========================= */
app.post("/api/login", async (req, res) => {

  const { username, password } = req.body;

  try {

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({
        error: "User not found"
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        error: "Your account is suspended by admin ❌"
      });
    }

    /// CHECK PASSWORD
    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {
      return res.status(401).json({
        error: "Wrong password"
      });
    }

    /// CREATE TOKEN
    const token = jwt.sign(
      {
        id: user._id,
        role: user.role || "user"
      },
      SECRET,
      { expiresIn: "1d" }
    );

    /// FORCE PASSWORD CHANGE
    if (user.forcePasswordChange) {

      return res.json({
        token,
        role: user.role,
        forcePasswordChange: true,
      });

    }

    /// NORMAL LOGIN
    res.json({
      token,
      userId: user._id,
      role: user.role || "user",
      forcePasswordChange: false,
    });

  } catch (err) {

    console.log(err);

    res.status(500).json({
      error: "Server error"
    });

  }

});

/* ===========================
      GENERATE TEMP PASSWORD
============================*/

app.post("/api/generate-temp-password", async (req, res) => {

  const { username, email } = req.body;

  try {

    const user = await User.findOne({
      username,
      email,
    });

    if (!user) {
      return res.status(400).json({
        error: "Invalid username or email"
      });
    }

    /// TEMP PASSWORD
    const tempPassword =
        "TMP" + Math.floor(100000 + Math.random() * 900000);

    /// HASH PASSWORD
    const hashed =
        await bcrypt.hash(tempPassword, 10);

    user.password = hashed;

    /// FORCE CHANGE PASSWORD
    user.forcePasswordChange = true;

    await user.save();

    res.json({
      success: true,
      tempPassword,
    });

  } catch (e) {

    res.status(500).json({
      error: e.toString(),
    });

  }

});

/*=================================================
            TRADE COMMAND MODEL
=================================================*/

const TradeCommandSchema =
    new mongoose.Schema({

  account: String,

  type: String,

  symbol: String,

  lot: Number,

  status: {
    type: String,
    default: "pending",
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const TradeCommand =
    mongoose.model(
      "TradeCommand",
      TradeCommandSchema,
    );

/*=================================================
            TRADE COMMAND API
=================================================*/

app.post("/api/trade-command", async (req, res) => {

  try {

    const {
      account,
      type,
      symbol,
      lot
    } = req.body;

    console.log("TRADE COMMAND:", req.body);

    await TradeCommand.create({

      account,
      type,
      symbol,
      lot,

      status: "pending",

      createdAt: new Date(),
    });

    res.json({

      success: true,

      message: "Trade command sent ✅",
    });

  } catch (e) {

    console.log("TRADE ERROR:", e);

    res.status(500).json({

      success: false,

      message: "Server Error ❌",
    });
  }
});

/*===================================================
			PENDING-COMMAND
===================================================*/

app.get("/api/pending-command", async (req, res) => {

  try {

    const account =
        req.query.account;

    const cmd =
        await TradeCommand.findOne({

      account,
      status: "pending",

    }).sort({ createdAt: 1 });

    if (!cmd) {

      return res.json({
        success: false,
      });
    }

    res.json({
      success: true,
      command: cmd,
    });

  } catch (e) {

    res.status(500).json({
      success: false,
    });
  }
});

/*===================================================
			COMPLETE-COMMAND
===================================================*/

app.post("/api/complete-command", async (req, res) => {

  try {

    const { id } = req.body;

    await TradeCommand.findByIdAndUpdate(
      id,
      {
        status: "completed",
      }
    );

    res.json({
      success: true,
    });

  } catch (e) {

    res.status(500).json({
      success: false,
    });
  }
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
	
  console.log(req.body);
	
  const {

	  account,
	  balance,
	  equity,
	  profit,
	  trades,

	  eaRunning,
	  mt5Connected,
	  vpsOnline,
	  ping,

	} = req.body;

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
    trades,

	  eaRunning,
	  mt5Connected,
	  vpsOnline,

	  lastUpdate: new Date(),

	  ping,
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
	
	user.forcePasswordChange = false;

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
  
  if (!user.isActive) {
	  return res.status(403).json({
		error: "Account suspended"
	  });
	}

  const data = await Data.find({
    account: { $in: user.accounts }
  });

  const result = user.accounts.map(acc => {
    const d = data.find(x => x.account === acc);

    const now = Date.now();

	const lastUpdate = d?.lastUpdate
	  ? new Date(d.lastUpdate).getTime()
	  : 0;

	const diff = now - lastUpdate;

	/// 30 seconds timeout
	const isLive = diff < 30000;

	return {
	  account: acc,

	  balance: d?.balance || null,
	  equity: d?.equity || null,
	  profit: d?.profit || null,

	  eaRunning: isLive && d?.eaRunning,
	  mt5Connected: isLive && d?.mt5Connected,
	  vpsOnline: isLive && d?.vpsOnline,

	  ping: isLive ? d?.ping || 0 : 0,

	  lastUpdate: d?.lastUpdate || null,

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

app.listen(PORT, "0.0.0.0", () => {
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