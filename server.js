require("dotenv").config();

const express = require("express");
const session = require("express-session");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*"
    }
});

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.log("Database error:", err.message);
        return;
    }

    console.log("✅ Database connected!");
});

app.use(cors({
    origin: true,
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000
    }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

app.use(express.static(__dirname));

io.use((socket, next) => {
    if (socket.request.session?.user) {
        return next();
    }
    next(new Error("Unauthorized"));
});

io.on("connection", socket => {
    const userId = socket.request.session.user.id;

    socket.join(`user:${userId}`);

    console.log("🟢 User connected:", userId);
});

app.get("/api/test", (req, res) => {
    res.json({
        success: true,
        message: "BariraProjects API is running!"
    });
});

// REGISTER
app.post("/api/register", async (req, res) => {
    try {
        const { name, username, email, password } = req.body;

        if (!name || !username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required!"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: "Password must contain at least 6 characters."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            "INSERT INTO users (name, username, email, password) VALUES (?, ?, ?, ?)",
            [name, username, email, hashedPassword],
            (err, result) => {
                if (err) {
                    return res.status(400).json({
                        success: false,
                        message: "Username or email already exists!"
                    });
                }

                res.json({
                    success: true,
                    message: "Account created successfully!",
                    userId: result.insertId
                });
            }
        );

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Registration failed."
        });
    }
});

// LOGIN
app.post("/api/login", (req, res) => {
    const { email, password } = req.body;

    db.query(
        "SELECT * FROM users WHERE email = ?",
        [email],
        async (err, results) => {
            if (err || results.length === 0) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid email or password."
                });
            }

            const user = results[0];

            const validPassword = await bcrypt.compare(
                password,
                user.password
            );

            if (!validPassword) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid email or password."
                });
            }

            req.session.user = {
                id: user.id,
                name: user.name,
                username: user.username,
                email: user.email
            };

            res.json({
                success: true,
                message: "Login successful!",
                user: req.session.user
            });
        }
    );
});

// CURRENT USER
app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Not logged in."
        });
    }

    res.json({
        success: true,
        user: req.session.user
    });
});

// LOGOUT
app.post("/api/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({
            success: true,
            message: "Logged out successfully."
        });
    });
});
// AUTHENTICATION CHECK
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Please login first!"
        });
    }

    next();
}


// GET ALL USER PROJECTS
app.get("/api/projects", requireLogin, (req, res) => {

    const userId = req.session.user.id;

    const sql = `
        SELECT p.*, pm.role
        FROM projects p
        JOIN project_members pm ON p.id = pm.project_id
        WHERE pm.user_id = ?
        ORDER BY p.created_at DESC
    `;

    db.query(sql, [userId], (err, results) => {

        if (err) {
            return res.status(500).json({
                success: false,
                message: "Could not load projects."
            });
        }

        res.json({
            success: true,
            projects: results
        });

    });

});


// CREATE NEW PROJECT
app.post("/api/projects", requireLogin, (req, res) => {

    const { name, description } = req.body;
    const userId = req.session.user.id;

    if (!name || !name.trim()) {
        return res.status(400).json({
            success: false,
            message: "Project name is required!"
        });
    }

    db.query(
        "INSERT INTO projects (name, description, owner_id) VALUES (?, ?, ?)",
        [name.trim(), description || "", userId],
        (err, result) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Project creation failed."
                });
            }

            const projectId = result.insertId;

            db.query(
                "INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, 'owner')",
                [projectId, userId],
                (memberError) => {

                    if (memberError) {
                        return res.status(500).json({
                            success: false,
                            message: "Project created, but membership setup failed."
                        });
                    }

                    res.json({
                        success: true,
                        message: "Project created successfully!",
                        projectId
                    });

                }
            );

        }
    );

});
// CHECK PROJECT MEMBERSHIP
function requireProjectMember(req, res, next) {
    const projectId = req.params.id;
    const userId = req.session.user.id;

    db.query(
        "SELECT role FROM project_members WHERE project_id = ? AND user_id = ?",
        [projectId, userId],
        (err, results) => {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Database error."
                });
            }

            if (results.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: "You are not a member of this project."
                });
            }

            req.projectRole = results[0].role;
            next();
        }
    );
}


// GET PROJECT DETAILS
app.get("/api/projects/:id", requireLogin, requireProjectMember, (req, res) => {

    db.query(
        "SELECT * FROM projects WHERE id = ?",
        [req.params.id],
        (err, results) => {

            if (err || results.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Project not found."
                });
            }

            res.json({
                success: true,
                project: results[0],
                role: req.projectRole
            });

        }
    );

});

// GET PROJECT TEAM MEMBERS
app.get("/api/projects/:id/members", requireLogin, requireProjectMember, (req, res) => {

    const projectId = req.params.id;

    const sql = `
        SELECT 
            u.id,
            u.name,
            u.username,
            pm.role
        FROM project_members pm
        JOIN users u ON pm.user_id = u.id
        WHERE pm.project_id = ?
        ORDER BY pm.role = 'owner' DESC, u.name ASC
    `;

    db.query(sql, [projectId], (err, members) => {

        if (err) {
            console.error("Members error:", err);
            return res.status(500).json({
                success: false,
                message: "Could not load team members"
            });
        }

        res.json({
            success: true,
            members: members
        });

    });
});
// GET PROJECT TASKS
app.get("/api/projects/:id/tasks", requireLogin, requireProjectMember, (req, res) => {

    const sql = `
        SELECT tasks.*, users.name AS assigned_name
        FROM tasks
        LEFT JOIN users ON tasks.assigned_to = users.id
        WHERE tasks.project_id = ?
        ORDER BY tasks.created_at DESC
    `;

    db.query(sql, [req.params.id], (err, results) => {

        if (err) {
            return res.status(500).json({
                success: false,
                message: "Could not load tasks."
            });
        }

        res.json({
            success: true,
            tasks: results
        });

    });

});

// GET ALL TASKS ASSIGNED TO LOGGED-IN USER

app.get("/api/my-tasks", requireLogin, (req, res) => {

    const userId = req.session.user.id;

    const sql = `
        SELECT 
            tasks.*,
            users.name AS assigned_name,
            projects.name AS project_name
        FROM tasks
        LEFT JOIN users ON tasks.assigned_to = users.id
        LEFT JOIN projects ON tasks.project_id = projects.id
        WHERE tasks.assigned_to = ?
        ORDER BY tasks.created_at DESC
    `;

    db.query(sql, [userId], (err, results) => {

        if (err) {
            console.error("My Tasks Error:", err);

            return res.status(500).json({
                success: false,
                message: "Could not load your tasks."
            });
        }

        res.json({
            success: true,
            tasks: results
        });

    });

});
// CREATE TASK WITH ACTIVITY LOG + REAL-TIME NOTIFICATION
app.post("/api/projects/:id/tasks", requireLogin, requireProjectMember, (req, res) => {

    const { title, description, priority, due_date, assigned_to } = req.body;

    if (!title || !title.trim()) {
        return res.status(400).json({
            success: false,
            message: "Task title is required."
        });
    }

    const projectId = req.params.id;
    const userId = req.session.user.id;
    const assignedUser = assigned_to || null;

    const insertTask = () => {

        const sql = `
            INSERT INTO tasks
            (project_id, assigned_to, created_by, title, description, priority, due_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

        db.query(sql, [
            projectId,
            assignedUser,
            userId,
            title.trim(),
            description || "",
            ["low", "medium", "high"].includes(priority) ? priority : "medium",
            due_date || null
        ], (err, result) => {

            if (err) {
                console.error("Task creation error:", err);

                return res.status(500).json({
                    success: false,
                    message: "Task creation failed."
                });
            }

            const taskId = result.insertId;

            // RECORD TASK CREATION IN ACTIVITY HISTORY
            db.query(
                `INSERT INTO task_activity (task_id, user_id, action, details)
                 VALUES (?, ?, ?, ?)`,
                [
                    taskId,
                    userId,
                    "Task Created",
                    `Created a new task: ${title.trim()}`
                ],
                (activityError) => {

                    if (activityError) {
                        console.error("Activity log error:", activityError);
                    }

                    // SEND REAL-TIME NOTIFICATION
                    const sendResponse = () => {

                        if (assignedUser && Number(assignedUser) !== Number(userId)) {

                            const notification = `You have been assigned a new task: ${title.trim()}`;

                            db.query(
                                "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
                                [assignedUser, notification],
                                (notificationError, notificationResult) => {

                                    if (!notificationError) {

                                        io.to(`user:${assignedUser}`).emit("notification:new", {
                                            id: notificationResult.insertId,
                                            message: notification,
                                            is_read: 0,
                                            created_at: new Date()
                                        });

                                    } else {
                                        console.error("Notification error:", notificationError);
                                    }

                                    res.json({
                                        success: true,
                                        message: "Task created successfully!",
                                        taskId: taskId
                                    });
                                }
                            );

                        } else {

                            res.json({
                                success: true,
                                message: "Task created successfully!",
                                taskId: taskId
                            });

                        }
                    };

                    sendResponse();

                }
            );

        });

    };

    // VERIFY ASSIGNED USER IS A PROJECT MEMBER
    if (assignedUser) {

        db.query(
            "SELECT id FROM project_members WHERE project_id = ? AND user_id = ?",
            [projectId, assignedUser],
            (err, results) => {

                if (err || results.length === 0) {
                    return res.status(400).json({
                        success: false,
                        message: "Assigned user is not a project member."
                    });
                }

                insertTask();
            }
        );

    } else {
        insertTask();
    }

});

// UPDATE TASK STATUS
app.patch("/api/tasks/:taskId/status", requireLogin, (req, res) => {

    const { status } = req.body;
    const userId = req.session.user.id;

    if (!["todo", "in_progress", "completed"].includes(status)) {
        return res.status(400).json({
            success: false,
            message: "Invalid task status."
        });
    }

    const sql = `
        UPDATE tasks
        JOIN project_members
        ON tasks.project_id = project_members.project_id
        SET tasks.status = ?
        WHERE tasks.id = ? AND project_members.user_id = ?
    `;

    db.query(sql, [status, req.params.taskId, userId], (err, result) => {

        if (err) {
            return res.status(500).json({
                success: false,
                message: "Could not update task."
            });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: "Task not found."
            });
        }
db.query(
    `INSERT INTO task_activity (task_id, user_id, action, details)
     VALUES (?, ?, ?, ?)`,
    [
        req.params.taskId,
        userId,
        "Status Changed",
        `Task status changed to ${status}.`
    ]
);
        res.json({
            success: true,
            message: "Task status updated!"
        });

    });

});
// DELETE TASK AND SAVE ALL DETAILS FOR RESTORATION
app.delete("/api/tasks/:taskId", requireLogin, (req, res) => {

    const taskId = req.params.taskId;
    const userId = req.session.user.id;

    const checkSql = `
        SELECT tasks.*
        FROM tasks
        JOIN project_members
        ON tasks.project_id = project_members.project_id
        WHERE tasks.id = ? AND project_members.user_id = ?
    `;

    db.query(checkSql, [taskId, userId], (err, results) => {

        if (err) {
            console.error(err);
            return res.status(500).json({
                success: false,
                message: "Database error."
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Task not found or access denied."
            });
        }

        const task = results[0];

        // SAVE COMPLETE TASK DETAILS
        const historySql = `
            INSERT INTO deleted_task_history
            (task_id, user_id, task_title, project_id, assigned_to,
             created_by, description, priority, due_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        db.query(historySql, [
            task.id,
            userId,
            task.title,
            task.project_id,
            task.assigned_to,
            task.created_by,
            task.description,
            task.priority,
            task.due_date,
            task.status
        ], (historyError) => {

            if (historyError) {
                console.error("History Error:", historyError);
                return res.status(500).json({
                    success: false,
                    message: "Could not save task history."
                });
            }

            // DELETE ORIGINAL TASK
            db.query(
                "DELETE FROM tasks WHERE id = ?",
                [taskId],
                (deleteError) => {

                    if (deleteError) {
                        console.error(deleteError);
                        return res.status(500).json({
                            success: false,
                            message: "Could not delete task."
                        });
                    }

                    res.json({
                        success: true,
                        message: "Task deleted and saved for restoration!"
                    });

                }
            );

        });

    });

});
// GET RECENTLY DELETED TASKS
app.get("/api/deleted-tasks", requireLogin, (req, res) => {

    const userId = req.session.user.id;

    const sql = `
        SELECT 
            deleted_task_history.*,
            projects.name AS project_name,
            users.name AS deleted_by
        FROM deleted_task_history
        JOIN projects
            ON deleted_task_history.project_id = projects.id
        JOIN project_members
            ON projects.id = project_members.project_id
        JOIN users
            ON deleted_task_history.user_id = users.id
        WHERE project_members.user_id = ?
        ORDER BY deleted_task_history.deleted_at DESC
    `;

    db.query(sql, [userId], (err, results) => {

        if (err) {
            console.error("Deleted Tasks Error:", err);
            return res.status(500).json({
                success: false,
                message: "Could not load deleted tasks."
            });
        }

        res.json({
            success: true,
            tasks: results
        });

    });

});
// EDIT TASK DETAILS
app.patch("/api/tasks/:taskId", requireLogin, (req, res) => {

    const { title, description, priority, due_date } = req.body;
    const userId = req.session.user.id;
    const taskId = req.params.taskId;

    if (!title || !title.trim()) {
        return res.status(400).json({
            success: false,
            message: "Task title is required."
        });
    }

    if (!["low", "medium", "high"].includes(priority)) {
        return res.status(400).json({
            success: false,
            message: "Invalid priority."
        });
    }

    const sql = `
        UPDATE tasks
        JOIN project_members
        ON tasks.project_id = project_members.project_id
        SET
            tasks.title = ?,
            tasks.description = ?,
            tasks.priority = ?,
            tasks.due_date = ?
        WHERE tasks.id = ?
        AND project_members.user_id = ?
    `;

    db.query(
        sql,
        [
            title.trim(),
            description || "",
            priority,
            due_date || null,
            taskId,
            userId
        ],
        (err, result) => {

            if (err) {
                console.error("Edit Task Error:", err);

                return res.status(500).json({
                    success: false,
                    message: "Could not edit task."
                });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Task not found."
                });
            }

        db.query(
    `INSERT INTO task_activity (task_id, user_id, action, details)
     VALUES (?, ?, ?, ?)`,
    [
        taskId,
        userId,
        "Task Updated",
        "Task title, description, priority or due date was updated."
    ]
);

res.json({
    success: true,
    message: "Task updated successfully."
});

        }
    );

});
// GET TASK ACTIVITY HISTORY
app.get("/api/tasks/:taskId/activity", requireLogin, (req, res) => {

    const userId = req.session.user.id;
    const taskId = req.params.taskId;

    const sql = `
        SELECT 
            task_activity.*,
            users.name AS user_name
        FROM task_activity
        JOIN users ON task_activity.user_id = users.id
        JOIN tasks ON task_activity.task_id = tasks.id
        JOIN project_members 
            ON tasks.project_id = project_members.project_id
        WHERE task_activity.task_id = ?
        AND project_members.user_id = ?
        ORDER BY task_activity.created_at DESC
    `;

    db.query(sql, [taskId, userId], (err, results) => {

        if (err) {
            console.error("Activity Error:", err);
            return res.status(500).json({
                success: false,
                message: "Could not load activity."
            });
        }

        res.json({
            success: true,
            activities: results
        });

    });

});
// GET TASK COMMENTS
app.get("/api/tasks/:taskId/comments", requireLogin, (req, res) => {

    const sql = `
        SELECT c.*, u.name AS user_name
        FROM task_comments c
        JOIN users u ON c.user_id = u.id
        JOIN tasks t ON c.task_id = t.id
        JOIN project_members pm ON pm.project_id = t.project_id
        WHERE c.task_id = ? AND pm.user_id = ?
        ORDER BY c.created_at ASC
    `;

    db.query(sql, [req.params.taskId, req.session.user.id], (err, results) => {

        if (err) {
            return res.status(500).json({
                success: false,
                message: "Could not load comments."
            });
        }

        res.json({
            success: true,
            comments: results
        });

    });

});


// ADD TASK COMMENT WITH DEBUGGING
app.post("/api/tasks/:taskId/comments", requireLogin, (req, res) => {

    const { comment } = req.body;
    const userId = Number(req.session.user.id);
    const userName = req.session.user.name;
    const taskId = req.params.taskId;

    console.log("\n========== COMMENT DEBUG ==========");
    console.log("Commenting user:", userId);
    console.log("Task ID:", taskId);
    console.log("Comment:", comment);

    if (!comment || !comment.trim()) {
        return res.status(400).json({
            success: false,
            message: "Comment cannot be empty."
        });
    }

    const sql = `
        SELECT t.id, t.title, t.created_by, t.assigned_to
        FROM tasks t
        JOIN project_members pm ON pm.project_id = t.project_id
        WHERE t.id = ? AND pm.user_id = ?
    `;

    db.query(sql, [taskId, userId], (err, results) => {

        if (err) {
            console.error("TASK QUERY ERROR:", err);
            return res.status(500).json({
                success: false,
                message: "Task database error."
            });
        }

        if (results.length === 0) {
            console.log("Task not found or user is not a member.");

            return res.status(403).json({
                success: false,
                message: "You cannot comment on this task."
            });
        }

        const task = results[0];

        console.log("Task found:", task);

        db.query(
            "INSERT INTO task_comments (task_id, user_id, comment) VALUES (?, ?, ?)",
            [taskId, userId, comment.trim()],
            (commentError, result) => {

                if (commentError) {
                    console.error("COMMENT INSERT ERROR:", commentError);

                    return res.status(500).json({
                        success: false,
                        message: "Comment could not be saved."
                    });
                }

                console.log("Comment saved:", result.insertId);

                const recipients = [
                    task.created_by,
                    task.assigned_to
                ]
                .filter(id => id && Number(id) !== userId);

                const uniqueRecipients = [...new Set(recipients)];

                console.log("Notification recipients:", uniqueRecipients);

                res.json({
                    success: true,
                    message: "Comment added!",
                    commentId: result.insertId
                });

                uniqueRecipients.forEach(receiverId => {

                    const notification =
                        `${userName} commented on your task: ${task.title}`;

                    db.query(
                        "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
                        [receiverId, notification],
                        (notificationError, notificationResult) => {

                            if (notificationError) {
                                console.error(
                                    "NOTIFICATION INSERT ERROR:",
                                    notificationError
                                );
                                return;
                            }

                            console.log("Notification saved for:", receiverId);

                            io.to(`user:${receiverId}`).emit("notification:new", {
                                id: notificationResult.insertId,
                                message: notification,
                                is_read: 0,
                                created_at: new Date()
                            });

                            console.log("Socket notification emitted to:", receiverId);

                        }
                    );

                });

            }
        );

    });

});
// GET PROJECT MEMBERS
app.get("/api/projects/:id/members", requireLogin, requireProjectMember, (req, res) => {

    const sql = `
        SELECT u.id, u.name, u.username, u.email, pm.role
        FROM project_members pm
        JOIN users u ON pm.user_id = u.id
        WHERE pm.project_id = ?
        ORDER BY pm.joined_at ASC
    `;

    db.query(sql, [req.params.id], (err, results) => {

        if (err) {
            return res.status(500).json({
                success: false,
                message: "Could not load team members."
            });
        }

        res.json({
            success: true,
            members: results
        });

    });

});


// ADD TEAM MEMBER
app.post("/api/projects/:id/members", requireLogin, requireProjectMember, (req, res) => {

    const { username } = req.body;
    const projectId = req.params.id;

    if (!username || !username.trim()) {
        return res.status(400).json({
            success: false,
            message: "Enter a username."
        });
    }

    if (!["owner", "admin"].includes(req.projectRole)) {
        return res.status(403).json({
            success: false,
            message: "Only project owners and admins can add members."
        });
    }

    db.query(
        "SELECT id, name, username FROM users WHERE username = ?",
        [username.trim()],
        (err, users) => {

            if (err || users.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: "User not found. Check the username."
                });
            }

            const member = users[0];

            db.query(
                "INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, 'member')",
                [projectId, member.id],
                (insertError) => {

                    if (insertError) {
                        return res.status(400).json({
                            success: false,
                            message: "This user is already a project member."
                        });
                    }

                    const notification = `You were added to a project by ${req.session.user.name}.`;

                    db.query(
                        "INSERT INTO notifications (user_id, message) VALUES (?, ?)",
                        [member.id, notification],
                        (notificationError, notificationResult) => {

                            if (!notificationError) {
                                io.to(`user:${member.id}`).emit("notification:new", {
                                    id: notificationResult.insertId,
                                    message: notification,
                                    is_read: 0
                                });
                            }

                        }
                    );

                    res.json({
                        success: true,
                        message: member.name + " added successfully!"
                    });

                }
            );

        }
    );

});


// GET MY NOTIFICATIONS
app.get("/api/notifications", requireLogin, (req, res) => {

    db.query(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC",
        [req.session.user.id],
        (err, results) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not load notifications."
                });
            }

            res.json({
                success: true,
                notifications: results
            });

        }
    );

});


// MARK NOTIFICATION AS READ
app.patch("/api/notifications/:id/read", requireLogin, (req, res) => {

    db.query(
        "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
        [req.params.id, req.session.user.id],
        (err, result) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not update notification."
                });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Notification not found."
                });
            }

            res.json({
                success: true,
                message: "Notification marked as read."
            });

        }
    );

});


// MARK ALL NOTIFICATIONS AS READ
app.patch("/api/notifications/read-all", requireLogin, (req, res) => {

    db.query(
        "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
        [req.session.user.id],
        (err) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Could not update notifications."
                });
            }

            res.json({
                success: true,
                message: "All notifications marked as read."
            });

        }
    );

});

// RESTORE DELETED TASK
app.post("/api/deleted-tasks/:id/restore", requireLogin, (req, res) => {

    const historyId = req.params.id;
    const userId = req.session.user.id;

    const sql = `
        SELECT d.*
        FROM deleted_task_history d
        JOIN project_members pm
        ON d.project_id = pm.project_id
        WHERE d.id = ? AND pm.user_id = ?
    `;

    db.query(sql, [historyId, userId], (err, results) => {

        if (err) {
            console.error(err);
            return res.status(500).json({
                success: false,
                message: "Database error."
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Deleted task not found."
            });
        }

        const task = results[0];

        const restoreSql = `
            INSERT INTO tasks
            (project_id, assigned_to, created_by, title,
             description, priority, due_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;

        db.query(restoreSql, [
            task.project_id,
            task.assigned_to,
            task.created_by,
            task.task_title,
            task.description,
            task.priority,
            task.due_date,
            task.status || "todo"
        ], (restoreError) => {

            if (restoreError) {
                console.error(restoreError);
                return res.status(500).json({
                    success: false,
                    message: "Could not restore task."
                });
            }

            db.query(
                "DELETE FROM deleted_task_history WHERE id = ?",
                [historyId],
                (deleteError) => {

                    if (deleteError) {
                        console.error(deleteError);
                        return res.status(500).json({
                            success: false,
                            message: "Task restored, but history cleanup failed."
                        });
                    }

                    res.json({
                        success: true,
                        message: "Task restored successfully!"
                    });

                }
            );

        });

    });

});
app.get("/", (req, res) => {
    res.send("BariraProjects Server is Running! 🚀");
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`🚀 BariraProjects running at http://localhost:${PORT}`);
});