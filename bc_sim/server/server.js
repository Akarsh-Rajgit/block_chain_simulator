const express = require("express");
const { exec } = require("child_process");
const path = require("path");
const cors = require("cors");

const app = express();
const PORT = 3000;

// Enable CORS so the browser (index.html) can talk to this server
app.use(cors());

// Optional: Serve static files from the frontend folder if you want
// app.use(express.static(path.join(__dirname, "../frontend")));

app.get("/status", (req, res) => {
    /**
     * path.join ensures this works on both Windows and Linux/Mac.
     * We are looking for 'blockchain.exe' inside the 'core' folder.
     * If you are on Mac/Linux, change 'blockchain.exe' to './blockchain'
     */
    const exePath = path.join(__dirname, "../core/blockchain.exe");

    exec(`"${exePath}"`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Exec Error: ${error}`);
            return res.status(500).json({ 
                error: "Failed to run blockchain engine", 
                details: error.message 
            });
        }

        if (stderr) {
            console.error(`C++ Stderr: ${stderr}`);
        }

        try {
            // C++ prints a JSON string to stdout; we parse it here
            const blockchainData = JSON.parse(stdout);
            res.json(blockchainData);
        } catch (parseError) {
            console.error("Failed to parse C++ output:", stdout);
            res.status(500).json({ 
                error: "Invalid data format from engine", 
                raw: stdout 
            });
        }
    });
});

app.listen(PORT, () => {
    console.log(`-----------------------------------------`);
    console.log(`✅ Server is running at http://localhost:${PORT}`);
    console.log(`🚀 Click 'Check Status' in your browser!`);
    console.log(`-----------------------------------------`);
});