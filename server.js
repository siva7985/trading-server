const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

const SECRET = "my_secret_key"; // 🔐 change later

let command = "";
let latestData = {};

// 🔐 LOGIN API
app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    if (username === "admin" && password === "1234") {
        const token = jwt.sign({ username }, SECRET, { expiresIn: "1d" });
        return res.json({ token });
    }

    res.status(401).json({ error: "Invalid credentials" });
});

// 🔐 MIDDLEWARE
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) return res.status(403).send("No token");

    const token = authHeader.split(" ")[1];

    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).send("Invalid token");
        req.user = user;
        next();
    });
}

// 🔐 PROTECTED COMMAND API
app.post("/api/send-command", authenticate, (req, res) => {
    command = req.body.command;
    console.log("COMMAND:", command);
    res.send("OK");
});

// EA fetch (no auth for now)
app.get("/api/command", (req, res) => {
    res.send(command);
    command = "";
});

// Data APIs
app.post("/api/update", (req, res) => {
    latestData = req.body;
    res.send("OK");
});

app.get("/api/data", (req, res) => {
    res.json(latestData);
});

app.listen(3000, () => console.log("Server started"));