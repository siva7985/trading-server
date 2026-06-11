require("dotenv").config({
  quiet: true
});

const http = require("http");
const { Server } = require("socket.io");

const SECRET_KEY = process.env.SECRET_KEY;

const express = require("express");

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.set("trust proxy", 1);

const cors = require("cors");

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.options("*", cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const SECRET = process.env.JWT_SECRET;


function verifySecret(req, res, next){

    const secret =
        req.headers.secret ||
        req.body.secret ||
        req.query.secret;

    if(secret !== SECRET_KEY){

        return res.status(401).json({
            error: "Unauthorized"
        });

    }

    next();
}

const mongoSanitize = require("express-mongo-sanitize");

app.use(mongoSanitize());

const helmet = require("helmet");

app.use(helmet());

/* =========================
   🔗 MONGODB CONNECT
========================= */
mongoose.connect(process.env.MONGO_URI)
.then(async () => {
  console.log("MongoDB Connected ✅");

})
.catch(err => {
  console.log("MongoDB ERROR ❌");
  console.log(err);
});

const ONLINE_TIMEOUT = 120000;

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
  
  accounts: [
	  {
		account: {
		  type: String,
		  required: true
		},

		accountName: {
		  type: String,
		  default: ""
		},

		accountType: {
		  type: String,
		  enum: ["Demo", "Real"],
		  default: "Real"
		},

		currency: {
		  type: String,
		  default: "USD"
		},

		platform: {
		  type: String,
		  enum: ["MT4", "MT5"],
		  default: "MT5"
		},

		server: {
		  type: String,
		  default: ""
		},

		createdAt: {
		  type: Date,
		  default: Date.now
		}
	  }
	],

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

    accountStatus: {
	  type: String,
	  enum: ["ACTIVE", "INACTIVE", "SUSPENDED"],
	  default: "INACTIVE"
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
	
	/// ✅ USER ONLINE TRACKING
  lastSeen: {
    type: Date,
    default: null
  },
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
  
  prices: Object,

  trades: Array,
  
  settings: {
    type: mongoose.Schema.Types.Mixed,
    default: []
  },

  pendingSettings: mongoose.Schema.Types.Mixed,

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

/*================================
       EAActivation
==================================*/

const EAActivation =
  require("./models/EAActivation");

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
      return res.status(401).json({
		   error: "Invalid username or password"
		});
    }

    res.json(user);

  } catch (err) {
    console.log("FETCH USER ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/users", auth, async (req, res) => {

  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Access denied"
    });
  }

  const users = await User.find(
	  { role: "user" }
	).select(
	  "-password -otp -otpExpiry -__v"
	);

  // ✅ Collect all accounts from all users
  const allAccounts = users.flatMap(
    user => (user.accounts || []).map(a => a.account)
  );

  // ✅ Single MongoDB query
  const allData = await Data.find({
    account: { $in: allAccounts }
  });

  // ✅ Fast lookup map
  const dataMap = new Map();

  allData.forEach(d => {
    dataMap.set(d.account, d);
  });

  const now = Date.now();

  const result = users.map(user => {

    const accountNumbers =
      (user.accounts || []).map(a => a.account);

    // ✅ Get account data from memory
    const data = accountNumbers
      .map(acc => dataMap.get(acc))
      .filter(Boolean);

    const tradingOnline = data.some(d => {

      if (!d.lastUpdate) return false;

      const diff =
        now - new Date(d.lastUpdate).getTime();

      return diff < ONLINE_TIMEOUT;

    });

    const userOnline =
      user.lastSeen &&
      (now - new Date(user.lastSeen).getTime()) < 60000;

    return {

      ...user.toObject(),

      userOnline,

      tradingOnline,

      accountDebug: data.map(d => ({
        account: d.account,
        lastUpdate: d.lastUpdate,
        diff:
          now - new Date(d.lastUpdate).getTime()
      }))

    };

  });

  res.json(result);

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

app.post("/api/ping-user", auth, async (req, res) => {

  try {

    //console.log("PING RECEIVED FROM =", req.user.id);

    const updatedUser =
      await User.findByIdAndUpdate(

        req.user.id,

        {
          $set: {
            lastSeen: new Date()
          }
        },

        {
          new: true
        }
      );

    //console.log("UPDATED USER =", updatedUser);

    res.json({
      success: true
    });

  } catch (e) {

    console.log("PING ERROR =", e);

    res.status(500).json({
      success: false
    });

  }

});

/* =========================
   📊 ADMIN → USER TRADES
========================= */

app.get("/api/admin/user-data/:userId", auth, async (req, res) => {

  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied" });
  }

  const { userId } = req.params;

  const user = await User.findById(userId);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const accountNumbers =
    user.accounts.map(a => a.account);

  const data = await Data.find({
    account: { $in: accountNumbers }
  });
  
  console.log(
    "DATA FROM DB IN USER-DATA API =",
    JSON.stringify(data, null, 2)
  );

  const now = Date.now();

  const tradingOnline = data.some(d => {

    if (!d.lastUpdate) return false;

    const diff =
      now - new Date(d.lastUpdate).getTime();

    return diff < ONLINE_TIMEOUT; // 30 seconds
  });

  const result = user.accounts.map(acc => {

    const d = data.find(
      x => x.account === acc.account
    );

    const isOnline =
	  d?.lastUpdate &&
	  (Date.now() - new Date(d.lastUpdate).getTime()) < ONLINE_TIMEOUT;

	return {
	  account: acc.account,
	  accountName: acc.accountName || "",
	  accountType: acc.accountType || "",
	  currency: acc.currency || "",
	  platform: acc.platform || "",
	  server: acc.server || "",

	  balance: d?.balance || 0,
	  equity: d?.equity || 0,
	  profit: d?.profit || 0,

	  tradingOnline: isOnline,

	  trades: d?.trades || []
	};
  });
  
  /*console.log("ACCOUNT DATA =", data);
	console.log("NOW =", now);

	data.forEach(d => {
	  console.log(
		d.account,
		d.lastUpdate,
		now - new Date(d.lastUpdate).getTime()
	  );
	});*/
	
 //console.log("FINAL TRADING ONLINE =", tradingOnline);

  res.json({

    fullName: user.fullName,
    email: user.email,
    username: user.username,

    isActive: user.isActive,

    tradingOnline: tradingOnline,

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

const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
   windowMs: 15 * 60 * 1000,
   max: 10
});

app.post("/api/login", loginLimiter, async (req, res) => {

  const { username, password } = req.body;

  try {

    const user = await User.findOne({
	   username: new RegExp("^" + username + "$", "i")
	});

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
		   error: "Invalid username or password"
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

    console.log("LOGIN ERROR:", err);

    res.status(500).json({
      error: err.message
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
=================================================

const TradeCommandSchema =
    new mongoose.Schema({

  account: String,

  type: String,

  symbol: String,

  lot: Number,
  
  price: Number,

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
    );*/
	
const CommandSchema = new mongoose.Schema({

  account: {
    type: String,
    required: true
  },

  command: {
    type: String,
    required: true
  },
  
  symbol: String,

  lot: Number,

  price: Number,
  
  ticket: Number,
  
  sl: Number,
  tp: Number,

  status: {
    type: String,
    enum: ["pending", "processing", "completed"],
    default: "pending"
  },

  createdAt: {
    type: Date,
    default: Date.now
  }

});

/// ✅ AUTO DELETE AFTER 24 HOURS
CommandSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 86400 }
);

CommandSchema.index({
  account: 1,
  status: 1,
  createdAt: 1
});

const Command = mongoose.model("Command", CommandSchema);


/* =========================
   ➕ ADD ACCOUNT
========================= */
app.post("/api/add-account", auth, async (req, res) => {
  const userId = req.user.id;
  const {
	  account,
	  accountName,
	  accountType,
	  currency,
	  platform,
	  server
	} = req.body;

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

  const exists =
	  user.accounts.some(
		a => a.account === account
	  );

	if (exists) {
	  return res.status(400).json({
		error:"Already added"
	  });
	}

  // ❗ Prevent same account in multiple users
  const existing =
	 await User.findOne({
	   "accounts.account": account
	 });
  if (existing) {
    return res.status(400).json({ error: "Account already used by another user" });
  }

  user.accounts.push({
	  account,
	  accountName,
	  accountType,
	  currency,
	  platform,
	  server
	});
  await user.save();
  
  global.io.to(userId).emit("users_updated", {
	  source: "add-account"
	});

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
app.post("/api/update", verifySecret, async (req, res) => {

  //console.log(req.body);
  
  //console.log(JSON.stringify(req.body, null, 2));
  
  const {
    account,
    balance,
    equity,
    profit,
    prices,
    trades,
    settings,

    eaRunning,
    mt5Connected,
    vpsOnline,
    ping,
  } = req.body;

  const user =
	 await User.findOne({
	   "accounts.account": account
	 });

  if (!user) {
    return res.status(403).send("Account not linked");
  }

  // ✅ KEEP EXISTING SETTINGS
  const existingData = await Data.findOne({ account });

  const finalSettings =
	  settings && settings.length > 0
		? settings
		: existingData?.settings || [];

  /*await Data.findOneAndUpdate(
    { userId: user._id, account },

    {
      userId: user._id,

      account,
      balance,
      equity,
      profit,

      prices,
      trades,

      settings: finalSettings,

      eaRunning,
      mt5Connected,
      vpsOnline,

      lastUpdate: new Date(),

      ping,
    },

    {
      upsert: true,
      new: true
    }
  );*/
  
  const updated = await Data.findOneAndUpdate(
	  { userId: user._id, account },
	  {
		userId: user._id,
		account,
		balance,
		equity,
		profit,
		prices,
		trades,
		settings: finalSettings,
		eaRunning,
		mt5Connected,
		vpsOnline,
		lastUpdate: new Date(),
		ping,
	  },
	  {
		upsert: true,
		new: true
	  }
	);
	
	global.io.to(user._id.toString()).emit("account_live", {
	  account,
	  balance,
	  equity,
	  profit,
	  prices,
	  trades,
	  lastUpdate: new Date()
	});

	/*console.log(
	  "UPDATE RECEIVED:",
	  account,
	  "PROFIT:",
	  profit,
	  "EQUITY:",
	  equity,
	  "TRADES:",
	  trades?.length || 0
	);

	console.log(
	  "DB SAVED:",
	  updated.account,
	  updated.profit,
	  updated.equity,
	  updated.lastUpdate
	);*/

  res.send("OK");
});

/* =========================
   📊 update-account
========================= */

app.post("/api/update-account", auth, async (req, res) => {
	console.log("UPDATE ACCOUNT API HIT 🚀");
	
  try {
    const userId = req.user.id;

    const {
      oldAccount,
      newAccount,
      accountName,
      accountType
    } = req.body;

    // Validate required fields
    if (
      !oldAccount ||
      !newAccount ||
      !accountName ||
      !accountType
    ) {
      return res.status(400).json({
        error: "Missing fields"
      });
    }

    // Validate account number
    if (!isValidAccount(newAccount)) {
      return res.status(400).json({
        error: "Account must be exactly 9 digits (numbers only)"
      });
    }

    // Validate account type
    if (
      accountType !== "Real" &&
      accountType !== "Demo"
    ) {
      return res.status(400).json({
        error: "Invalid account type"
      });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    const accountObj = user.accounts.find(
      acc => acc.account === oldAccount
    );

    if (!accountObj) {
      return res.status(400).json({
        error: "Account not found"
      });
    }

    // Prevent duplicate account numbers
    if (oldAccount !== newAccount) {

      const existing = await User.findOne({
        "accounts.account": newAccount
      });

      if (existing) {
        return res.status(400).json({
          error: "Account already used"
        });
      }
    }

    // Update account
    user.accounts = user.accounts.map(acc => {

      if (acc.account === oldAccount) {

        acc.account = newAccount;
        acc.accountName = accountName;
        acc.accountType = accountType;
      }

      return acc;
    });

    await user.save();

    // Update Data collection
    await Data.updateMany(
      { account: oldAccount },
      {
        $set: {
          account: newAccount,
          accountName: accountName,
          accountType: accountType
        }
      }
    );
	
	console.log("CONNECTED CLIENTS:", global.io.engine.clientsCount);

	global.io.to(userId).emit("users_updated", {
	  source: "update-account"
	});

	console.log("USERS_UPDATED EVENT SENT 🚀");

    res.json({
      success: true,
      message: "Account updated successfully"
    });

  } catch (err) {

    console.log("UPDATE ACCOUNT ERROR:", err);

    res.status(500).json({
      error: "Server error"
    });
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
	
	global.io.to(userId).emit("users_updated", {
	  source: "update-profile"
	});

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

    const exists = user.accounts.some(
	  a => a.account === account
	);

	if (!exists) {
	  return res.status(400).json({
		error: "Account not found"
	  });
	}

    // ✅ Remove from user only
    user.accounts =
	 user.accounts.filter(
	   acc => acc.account !== account
	 );
    await user.save();
	
	global.io.to(userId).emit("users_updated", {
	  source: "delete-account"
	});

    // ✅ Optional: remove its data (recommended)
    await Data.deleteMany({ account });

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

  if (!user?.isActive) {
    return res.status(403).json({ error: "Account suspended" });
  }

  const accountNumbers = (user.accounts || []).map(a => a.account);

  const data = await Data.find({
    account: { $in: accountNumbers }
  });

  const dataMap = new Map(data.map(d => [d.account, d]));

  const now = Date.now();

  const result = (user.accounts || []).map(accObj => {
    const accountNumber = accObj.account;
    const d = dataMap.get(accountNumber);

    const lastUpdate = d?.lastUpdate
      ? new Date(d.lastUpdate).getTime()
      : 0;

    const isLive = now - lastUpdate < ONLINE_TIMEOUT;

    return {
      account: accountNumber,
      tradingOnline: isLive,

      accountName: accObj.accountName || "",
      accountType: accObj.accountType || "",
      currency: accObj.currency || "",
      platform: accObj.platform || "",
      server: accObj.server || "",

      balance: d?.balance ?? null,
      equity: d?.equity ?? null,
      profit: d?.profit ?? null,

      prices: d?.prices || {},
      trades: d?.trades || [],
      settings: d?.settings || [],

      eaRunning: isLive && !!d?.eaRunning,
      mt5Connected: isLive && !!d?.mt5Connected,
      vpsOnline: isLive && !!d?.vpsOnline,

      ping: isLive ? (d?.ping || 0) : 0,
      lastUpdate: d?.lastUpdate || null
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
   📌 EA UPDATE-SETTINGS
========================= */
app.post("/api/update-settings", auth, async (req, res) => {

  try {

    const { account, settings } = req.body;

    //console.log("ACCOUNT:", account);
    //console.log("NEW SETTINGS:", settings);

    const data = await Data.findOne({ account });

    if (!data) {

      return res.json({
        success: false,
        error: "Account not found"
      });
    }

    //console.log("OLD SETTINGS:", data.settings);

    const updatedSettings = data.settings.map(item => {

	  const itemName = item.name.trim();

	  const matchedKey = Object.keys(settings).find(
		key =>
		  key.trim().toLowerCase() ===
		  itemName.toLowerCase()
	  );

	  if (matchedKey) {

		let newValue = settings[matchedKey];

		// BOOL SUPPORT
		if (item.type === "bool") {

		  newValue =
			newValue === true ||
			newValue === "true";

		}

		// NUMBER SUPPORT
		else if (item.type === "dropdown") {

		  newValue = String(newValue);

		}

		else {

		  newValue = Number(newValue);

		  if (isNaN(newValue)) {
			newValue = item.value;
		  }
		}

		return {
		  name: item.name,
		  type: item.type,
		  value: newValue,
		  options: item.options || []
		};
	  }

	  return item;
	});

    data.settings = updatedSettings;

    data.markModified("settings");

    await data.save();

    console.log("UPDATED SETTINGS:", data.settings);

    res.json({
      success: true,
      settings: data.settings
    });

  } catch (err) {

    console.log("UPDATE SETTINGS ERROR:", err);

    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/* =========================
   📥 GET SETTINGS
========================= */
app.get("/api/get-settings", verifySecret, async (req, res) => {

  try {

    const account = req.query.account;

    if (!account) {
      return res.json({});
    }

    const data = await Data.findOne({ account });

    if (!data || !data.settings) {
      return res.json({});
    }

    const result = {};

    data.settings.forEach(item => {

      result[item.name] = String(item.value);

    });

    res.json(result);

  } catch (err) {

    console.log("GET SETTINGS ERROR:", err);

    res.json({});
  }
});

/*======================================================
			MODIFY-TRADE
======================================================*/
app.post("/api/modify-trade", auth, async (req, res) => {

  try {

    const {
      account,
      ticket,
      sl,
      tp
    } = req.body;

    await Command.create({

      account,

      command: "MODIFY",

      ticket,

      sl,
      tp,

      status: "pending",

      createdAt: new Date()

    });

    res.json({
      success: true
    });

  } catch (e) {

    console.log("MODIFY ERROR:", e);

    res.status(500).json({
      success: false
    });

  }

});

/* =========================
   📌 COMMAND API
========================= */


app.post("/api/send-command", auth, async (req, res) => {

  try {
	  
	//console.log("SEND COMMAND BODY =", req.body);

    const {
		  command,
		  account,
		  ticket,
		  symbol,
		  lot,
		  price
		} = req.body;

    // ✅ CLEAN ACCOUNT
    const cleanAccount = String(account).trim();

    // ✅ CHECK USER
    const user = await User.findById(req.user.id);

    if (!user) {

      return res.status(404).json({
        error: "User not found"
      });

    }

    // ✅ CHECK ACCOUNT BELONGS TO USER
    const hasAccount =
	 user.accounts.some(
	   a => a.account === cleanAccount
	 );

	if (!hasAccount) {
	  return res.status(403).json({
		error:"Unauthorized account"
	  });
	}

    // ✅ REQUIRED VALIDATION
    if (!cleanAccount || !command) {

      return res.status(400).json({
        error: "Missing data"
      });

    }

    // ✅ ALLOWED COMMANDS
    const allowedCommands = [
	  "START",
	  "STOP",
	  "CLOSE_ALL",
	  "CLOSE_TRADE",
	  "MODIFY_TRADE",
	  "BUY",
	  "SELL"
	];

    // ✅ INVALID COMMAND BLOCK
    if (!allowedCommands.includes(command)) {

      return res.status(400).json({
        error: "Invalid command"
      });

    }

    // ✅ SAVE COMMAND TO DATABASE
    await Command.create({

	  account: cleanAccount,

	  command,

	  symbol,

	  lot,

	  price,

	  ticket: ticket || null,

	  status: "pending",

	  createdAt: new Date()

	});

    // ✅ SUCCESS
    res.json({
      success: true
    });

  } catch (err) {

    console.log("SEND COMMAND ERROR:", err);

    res.status(500).json({
      error: "Server error"
    });

  }

});

app.get("/api/command", verifySecret, async (req, res) => {

  try {

    const account = req.query.account;

    if (!account) {
      return res.json({
        success: false
      });
    }

    const cmd = await Command.findOneAndUpdate(
      {
        account,
        status: "pending"
      },
      {
        $set: {
          status: "processing"
        }
      },
      {
        sort: { createdAt: 1 },
        new: true
      }
    );

    if (!cmd) {
      return res.json({
        success: false
      });
    }

    console.log("SENDING COMMAND =", cmd);

    res.json({

      success: true,

      command: cmd.command,

      symbol: cmd.symbol,

      lot: cmd.lot,

      price: cmd.price,

      ticket: cmd.ticket,

      sl: cmd.sl,

      tp: cmd.tp,

      id: cmd._id

    });

  } catch (err) {

    console.log("GET COMMAND ERROR:", err);

    res.status(500).json({
      success: false
    });

  }

});

app.post("/api/ack", verifySecret, async (req, res) => {

  try {

    const id = req.query.id;

    if (!id) {

      return res.json({
        success: false,
        error: "Missing id"
      });

    }

    const cmd = await Command.findByIdAndUpdate(
      id,
      {
        $set: {
          status: "completed"
        }
      },
      {
        new: true
      }
    );

    if (!cmd) {

      return res.json({
        success: false,
        error: "Command not found"
      });

    }

    console.log("COMMAND COMPLETED =", id);

    res.json({
      success: true
    });

  } catch (err) {

    console.log("ACK ERROR =", err);

    res.status(500).json({
      success: false
    });

  }

});

app.post("/api/save-settings", async (req, res) => {

  try {

    //console.log("SAVE SETTINGS BODY =", req.body);

    const { account, settings } = req.body;

    if (!account || !settings) {

      return res.json({
        success: false,
        error: "Missing data"
      });
    }

    const updated = await User.updateOne(

      {
        "accounts.account": account
      },

      {
        $set: {
          [`eaSettings.${account}`]: settings
        }
      }
    );

    console.log("UPDATE RESULT =", updated);

    res.json({
      success: true
    });

  } catch (err) {

    console.log("SAVE SETTINGS ERROR =", err);

    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

app.post("/api/activate-ea", auth, async (req, res) => {

  try {

    const {
      account,
      eaId,
      lot,
      risk
    } = req.body;

    const activation =
      await EAActivation.findOneAndUpdate(
        {
          userId: req.user.id,
          account,
          eaId
        },
        {
          $set: {
            status: "active",
            settings: {
              lot,
              risk
            }
          }
        },
        {
          upsert: true,
          new: true
        }
      );

    res.json({
      success: true,
      activation
    });

  } catch (err) {

    console.log("ACTIVATE EA ERROR =", err);

    res.status(500).json({
      success: false
    });

  }

});



app.get("/api/test-activations", async (req, res) => {

  try {

    const activations =
      await EAActivation.find();

    res.json(activations);

  } catch (err) {

    console.log(err);

    res.status(500).json({
      success: false
    });

  }

});

/*===========================================
      Delete Old Commands from DB
===========================================*/
setInterval(async () => {

  try {

    const result = await Command.deleteMany({

      status: "completed",

      createdAt: {
        $lt: new Date(Date.now() - 86400000)
      }

    });

    console.log(
      "Old commands deleted:",
      result.deletedCount
    );

  } catch (err) {

    console.log(
      "Cleanup error:",
      err.message
    );
  }

}, 60 * 60 * 1000);
//============================================


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

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;

  if (!token) return next(new Error("No token"));

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = decoded;
    next();
  } catch (err) {
    next(new Error("Unauthorized"));
  }
});

global.io = io;

console.log("Socket.IO Ready ✅");

server.listen(PORT, () => {
  console.log("Server Running");
});

io.on("connection", (socket) => {

  console.log("Client Connected:", socket.id);

  socket.on("join", (userId) => {
	if (socket.user.id !== userId) return;

    socket.join(userId);

    console.log(
      "USER JOINED ROOM:",
      userId
    );
  });

  socket.on("disconnect", () => {

    console.log(
      "Client Disconnected:",
      socket.id
    );

  });

});