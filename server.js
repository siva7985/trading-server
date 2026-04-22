const express = require("express");
const cors = require("cors");

const app = express();

// 🔥 STRONG CORS FIX
app.use(cors({
    origin: "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"]
}));

app.use(express.json());

let command = "";
let latestData = {};

// Command APIs
app.get("/api/command", (req, res) => {
    res.send(command); // ✅ FIXED
    command = "";
});

app.post("/api/send-command", (req, res) => {
    command = req.body.command;
    res.send("OK");
});

// Data APIs
app.post("/api/update", (req, res) => {
    console.log("Received Data:", req.body);
    latestData = req.body;
    res.send("OK");
});

app.get("/api/data", (req, res) => {
    res.json(latestData);
});

app.listen(3000, () => console.log("Server started"));