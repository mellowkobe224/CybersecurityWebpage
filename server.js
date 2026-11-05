require("dotenv").config();

const express = require("express");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Process information submitted through HTML forms
app.use(express.urlencoded({ extended: true }));

// =============================================
// SESSION CONFIGURATION
// =============================================

// Store login information between website requests
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    cookie: {
        httpOnly: true,
        secure: false, // Use false for localhost HTTP
        sameSite: "lax",
        maxAge: 60 * 60 * 1000 // One hour
    }
}));

// =============================================
// MYSQL DATABASE CONNECTION
// =============================================

const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD,
    database: "cybersecurity_website_db",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// =============================================
// WEBSITE FILE ROUTES
// =============================================

// Serve existing website pages
const publicFiles = {
    "/": "index.html",
    "/index.html": "index.html",
    "/careers.html": "careers.html",
    "/skills.html": "skills.html",
    "/about.html": "about.html",
    "/register.html": "register.html",
    "/login.html": "login.html"
};

for (const [url, filename] of Object.entries(publicFiles)) {
    app.get(url, (req, res) => {
        res.sendFile(path.join(__dirname, filename));
    });
}

// Serve website CSS and JavaScript files
app.get("/style.css", (req, res) => {
    res.sendFile(path.join(__dirname, "style.css"));
});

app.get("/script.js", (req, res) => {
    res.sendFile(path.join(__dirname, "script.js"));
});

// Serve website images
app.use("/images", express.static(path.join(__dirname, "images")));

// =============================================
// PASSWORD HASHING AND VERIFICATION
// =============================================

const HASH_ITERATIONS = 120000;
const HASH_LENGTH = 64;

// Generate a secure password hash with a random salt
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");

    const hash = crypto.pbkdf2Sync(
        password,
        salt,
        HASH_ITERATIONS,
        HASH_LENGTH,
        "sha512"
    ).toString("hex");

    return `pbkdf2$${HASH_ITERATIONS}$${salt}$${hash}`;
}

// Verify a submitted password against its stored hash
async function verifyPassword(password, storedHash) {

    if (!storedHash) {
        return false;
    }

    // Support older bcrypt password hashes
    if (storedHash.startsWith("$2")) {
        return bcrypt.compare(password, storedHash);
    }

    // Verify PBKDF2 password hashes
    const parts = storedHash.split("$");

    if (parts.length !== 4 || parts[0] !== "pbkdf2") {
        return false;
    }

    const iterations = Number(parts[1]);
    const salt = parts[2];
    const originalHash = parts[3];

    if (
        !Number.isSafeInteger(iterations) ||
        iterations < 1 ||
        !/^[a-f0-9]+$/i.test(salt) ||
        !/^[a-f0-9]+$/i.test(originalHash) ||
        originalHash.length % 2 !== 0
    ) {
        return false;
    }

    const newHash = crypto.pbkdf2Sync(
        password,
        salt,
        iterations,
        originalHash.length / 2,
        "sha512"
    );

    const originalBuffer = Buffer.from(originalHash, "hex");

    return originalBuffer.length === newHash.length &&
        crypto.timingSafeEqual(originalBuffer, newHash);
}

// =============================================
// HTML RESPONSE AND MESSAGE FUNCTIONS
// =============================================

// Escape special characters before displaying user information
function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, character => {
        const replacements = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        };

        return replacements[character];
    });
}

// Display registration and login success or failure messages
function responsePage(res, title, message, success = true) {

    const heading = escapeHtml(title);
    const safeMessage = escapeHtml(message);
    const color = success ? "#187a42" : "#b42318";

    res.status(success ? 200 : 400).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${heading} | BlueShield Cyber</title>
            <link rel="stylesheet" href="/style.css">
        </head>

        <body>
            <header>
                <nav class="navbar">
                    <a href="/" class="logo">BlueShield Cyber</a>
                </nav>
            </header>

            <main class="result-container">
                <h1 style="color: ${color};">${heading}</h1>
                <p>${safeMessage}</p>

                <a href="/login.html" class="result-link">Login</a>
                <a href="/register.html" class="result-link">Sign Up</a>
                <a href="/" class="result-link">Home</a>
            </main>

            <footer>
                <p>&copy; 2026 BlueShield Cyber. All rights reserved.</p>
            </footer>
        </body>
        </html>
    `);
}

// =============================================
// SIGNUP ENDPOINT
// =============================================

// Accept registration information from register.html
app.post(["/signup", "/register"], async (req, res) => {

    try {
        // Retrieve information from the submitted form
        const fname = (req.body.fname || "").trim();
        const lname = (req.body.lname || "").trim();
        const email = (req.body.email || "").trim().toLowerCase();
        const username = (req.body.userName || "").trim();
        const password = req.body.password || "";

        // Make sure all required fields are provided
        if (!fname || !lname || !email || !username || !password) {
            return responsePage(
                res,
                "Registration Failed",
                "Please fill in all required fields.",
                false
            );
        }

        // Validate registration information
        if (
            fname.length > 100 ||
            lname.length > 100 ||
            email.length > 255 ||
            username.length < 3 ||
            username.length > 50 ||
            !/^[a-zA-Z0-9_.-]+$/.test(username) ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
            password.length < 8
        ) {
            return responsePage(
                res,
                "Registration Failed",
                "Check your information. Use a valid email, a username of 3-50 letters or numbers, and a password of at least 8 characters.",
                false
            );
        }

        // Combine first and last name into one database field
        const fullName = `${fname} ${lname}`;

        // Check whether the username or email already exists
        const [existingUsers] = await db.execute(
            `SELECT user_id FROM users
             WHERE username = ? OR email = ?
             LIMIT 1`,
            [username, email]
        );

        if (existingUsers.length > 0) {
            return responsePage(
                res,
                "Registration Failed",
                "That username or email is already registered.",
                false
            );
        }

        // Hash the password before saving it
        const passwordHash = hashPassword(password);

        // Insert the new account into the existing users table
        await db.execute(
            `INSERT INTO users
             (full_name, username, email, password_hash)
             VALUES (?, ?, ?, ?)`,
            [fullName, username, email, passwordHash]
        );

        // Display successful registration message
        return responsePage(
            res,
            "Registration Successful!",
            "Your BlueShield Cyber account has been created. You can now log in.",
            true
        );

    } catch (error) {
        console.error("Signup error:", error);

        if (error.code === "ER_DUP_ENTRY") {
            return responsePage(
                res,
                "Registration Failed",
                "That username or email is already in use.",
                false
            );
        }

        return responsePage(
            res,
            "Registration Error",
            "Something went wrong while creating your account. Check the server terminal.",
            false
        );
    }
});

// =============================================
// LOGIN ENDPOINT
// =============================================

// Verify the user's credentials and create a session
app.post("/login", async (req, res) => {

    try {
        // Read username and password from login form
        const username = (req.body.username || "").trim();
        const password = req.body.password || "";

        // Check that both fields are filled out
        if (!username || !password) {
            return responsePage(
                res,
                "Login Failed",
                "Please enter your username and password.",
                false
            );
        }

        // Find the account in the database
        const [users] = await db.execute(
            `SELECT user_id, full_name, username, password_hash
             FROM users
             WHERE username = ?
             LIMIT 1`,
            [username]
        );

        // Reject login if the username does not exist
        if (users.length === 0) {
            return responsePage(
                res,
                "Login Failed",
                "The login credentials were incorrect. Please try again.",
                false
            );
        }

        const user = users[0];

        // Compare the entered password with the stored hash
        const passwordMatches = await verifyPassword(
            password,
            user.password_hash
        );

        if (!passwordMatches) {
            return responsePage(
                res,
                "Login Failed",
                "The login credentials were incorrect. Please try again.",
                false
            );
        }

        // Regenerate the session ID after successful authentication
        await new Promise((resolve, reject) => {
            req.session.regenerate(error => {
                if (error) reject(error);
                else resolve();
            });
        });

        // Store the logged-in user's information in the session
        req.session.user = {
            user_id: user.user_id,
            username: user.username,
            full_name: user.full_name
        };

        // Save the session before redirecting
        await new Promise((resolve, reject) => {
            req.session.save(error => {
                if (error) reject(error);
                else resolve();
            });
        });

        // Send the logged-in user to their profile
        return res.redirect("/profile");

    } catch (error) {
        console.error("Login error:", error);

        return responsePage(
            res,
            "Login Error",
            "Something went wrong while logging in. Check the server terminal.",
            false
        );
    }
});

// =============================================
// PROFILE ENDPOINT
// =============================================

// Display the username stored in the current user's session
app.get("/profile", (req, res) => {

    // Only logged-in users can access the profile
    if (!req.session.user) {
        return res.redirect("/login.html");
    }

    // Retrieve and safely display user information from the session
    const username = escapeHtml(req.session.user.username);
    const fullName = escapeHtml(req.session.user.full_name);

    // Display the user's profile page
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">

            <title>My Profile | BlueShield Cyber</title>

            <link rel="stylesheet" href="/style.css">
        </head>

        <body>

            <header>
                <nav class="navbar">
                    <a href="/" class="logo">BlueShield Cyber</a>

                    <div class="nav-links">
                        <a href="/">Home</a>
                        <a href="/careers.html">Careers</a>
                        <a href="/skills.html">Skills</a>
                        <a href="/about.html">About</a>
                        <a href="/logout">Logout</a>
                    </div>
                </nav>
            </header>

            <main class="auth-page">
                <section class="auth-container">

                    <h1>My Profile</h1>

                    <p class="auth-description">
                        Welcome to your BlueShield Cyber account!
                    </p>

                    <div class="profile-details">
                        <h2>Account Information</h2>

                        <p><strong>Full Name:</strong> ${fullName}</p>

                        <p><strong>Username:</strong> ${username}</p>

                        <p>You are currently logged in.</p>
                    </div>

                    <!-- Link to destroy the current login session -->
                    <a href="/logout" class="auth-button profile-logout">
                        Log Out
                    </a>

                </section>
            </main>

            <footer>
                <p>&copy; 2026 BlueShield Cyber. All rights reserved.</p>
            </footer>

        </body>
        </html>
    `);
});

// =============================================
// LOGOUT ENDPOINT
// =============================================

// Destroy the user's session when the logout link is clicked
app.get("/logout", (req, res) => {

    // Remove the session from the session store
    req.session.destroy(error => {

        if (error) {
            console.error("Logout error:", error);

            return res.status(500).send(
                "Unable to log out. Please try again."
            );
        }

        // Remove the session cookie from the browser
        res.clearCookie("connect.sid", {
            path: "/",
            httpOnly: true,
            secure: false,
            sameSite: "lax"
        });

        // Return the user to the login page
        res.redirect("/login.html");
    });
});

// =============================================
// START SERVER
// =============================================

async function startServer() {

    try {
        // Check the MySQL database connection
        const connection = await db.getConnection();

        console.log("Connected to cybersecurity_website_db successfully.");

        connection.release();

        // Start the Express server
        app.listen(PORT, () => {
            console.log(
                `BlueShield Cyber server running at http://localhost:${PORT}`
            );
        });

    } catch (error) {
        console.error("Could not connect to the database.");
        console.error(error.message);
        process.exit(1);
    }
}

startServer();
