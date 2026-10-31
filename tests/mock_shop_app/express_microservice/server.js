// Node.js / Express Microservice for Bonus B-7 (Second Language & Framework Support)
const express = require('express');
const { exec, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const _ = require('lodash');

const app = express();
const JWT_SIGNING_SECRET = "express_hardcoded_jwt_secret_key_2026";

app.get('/api/v2/users/:uid', (req, res) => {
    const uid = req.params.uid;
    // CWE-89 Vulnerable SQL query in Express
    db.query(`SELECT * FROM users WHERE uid = '${uid}'`);
    res.send("ok");
});

app.get('/api/v2/users-safe/:uid', (req, res) => {
    const uid = req.params.uid;
    // B-2 Safe parameterized SQL query in Express
    db.query("SELECT * FROM users WHERE uid = ?", [uid]);
    res.send("safe");
});

app.post('/api/v2/exec', (req, res) => {
    const host = req.body.host;
    // CWE-78 Vulnerable Command Injection in Express
    exec(`nslookup ${host}`);
    res.send("done");
});
