const mysql = require("mysql2");

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "barira_project_management_tool"
});

db.connect((err) => {
    if (err) {
        console.error("❌ Database connection failed:", err.message);
        return;
    }

    console.log("✅ Connected to BariraProjects Database!");
});

module.exports = db;