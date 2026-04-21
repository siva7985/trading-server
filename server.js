const express = require("express");
const app = express();

app.use(express.json());

let command = "";

// EA reads command
app.get("/api/command", (req, res) => {
    res.send(command);
    command = ""; // reset after sending
});

// App / you send command
app.post("/api/send-command", (req, res) => {
    command = req.body.command;
    res.send("OK");
});

app.get("/", (req, res) => {
    res.send("Server Running");
});

app.listen(3000, () => console.log("Server started"));