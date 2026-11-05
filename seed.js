require("dotenv").config();

const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");

async function seedDatabase() {
    let connection;

    try {
        connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            port: process.env.DB_PORT || 3306,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: "cybersecurity_website_db"
        });

        const users = [
            {
                full_name: "Alex Morgan",
                username: "alexmorgan",
                email: "alex@example.com",
                password: "AlexDemo123!"
            },
            {
                full_name: "Jordan Lee",
                username: "jordanlee",
                email: "jordan@example.com",
                password: "JordanDemo123!"
            },
            {
                full_name: "Taylor Smith",
                username: "taylorsmith",
                email: "taylor@example.com",
                password: "TaylorDemo123!"
            },
            {
                full_name: "Casey Brown",
                username: "caseybrown",
                email: "casey@example.com",
                password: "CaseyDemo123!"
            }
        ];

        for (const user of users) {
            const passwordHash = await bcrypt.hash(user.password, 10);

            await connection.execute(
                `INSERT INTO users
                (full_name, username, email, password_hash)
                VALUES (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                full_name = VALUES(full_name),
                password_hash = VALUES(password_hash)`,
                [
                    user.full_name,
                    user.username,
                    user.email,
                    passwordHash
                ]
            );

            console.log(`Added or updated: ${user.username}`);
        }

        console.log("Sample users have been added successfully.");

    } catch (error) {
        console.error("Database seeding failed:", error);
    } finally {
        if (connection) {
            await connection.end();
        }
    }
}

seedDatabase();
