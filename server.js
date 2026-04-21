const express = require("express");
const app = express();

app.use(express.json());

let command = "";
let latestData = {};

// Command APIs
app.get("/api/command", (req, res) => {
    res.send(command);
    command = "";
});

app.post("/api/send-command", (req, res) => {
    command = req.body.command;
    res.send("OK");
});

// NEW: Data APIs
app.post("/api/update", (req, res) => {
    latestData = req.body;
    res.send("OK");
});

app.get("/api/data", (req, res) => {
    res.json(latestData);
});

app.listen(3000, () => console.log("Server started"));