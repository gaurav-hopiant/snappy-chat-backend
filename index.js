const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

require('dotenv').config({ debug: true });

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.APP_URL }));

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'your_password',
  database: process.env.DB_NAME || 'sticky_notes_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
// Middleware to verify token
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  console.log('Authenticate middleware - Token:', token);
  if (!token) {
    console.log('No token provided in request');
    return res.status(401).json({ message: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('Decoded JWT:', decoded);
    req.user_id = decoded.userId; // Use userId from token payload
    console.log('Authenticated user_id:', req.user_id);
    next();
  } catch (error) {
    console.error('Token verification failed:', error.message);
    return res.status(401).json({ message: 'Invalid token', details: error.message });
  }
};

// GET /user-data: Fetch user data
app.get('/user-data', authenticate, async (req, res) => {
  console.log('GET /user-data called for user_id:', req.user_id);
  try {
    const [rows] = await pool.query('SELECT * FROM user_data WHERE user_id = ?', [req.user_id]);
    if (rows.length === 0) {
      console.log('No data found for user_id:', req.user_id, 'Returning defaults');
      return res.json({
        tasks: [],
        tags: [],
        operators: [],
        show_tags_on_notes: true,
      });
    }
    const row = rows[0];
    console.log('Fetched data for user_id:', req.user_id, row);
    res.json({
      tasks: JSON.parse(row.tasks_json),
      tags: JSON.parse(row.tags_json),
      operators: JSON.parse(row.operators_json),
      show_tags_on_notes: row.show_tags_on_notes,
    });
  } catch (error) {
    console.error('MySQL error in GET /user-data:', error.message);
    res.status(500).json({ message: 'Server error', details: error.message });
  }
});

// POST /user-data: Save user data
app.post('/user-data', authenticate, async (req, res) => {
  const { tasks, tags, operators, show_tags_on_notes } = req.body;
  console.log('POST /user-data called for user_id:', req.user_id, 'Data:', { tasks, tags, operators, show_tags_on_notes });
  try {
    await pool.query(
      `INSERT INTO user_data (user_id, tasks_json, tags_json, operators_json, show_tags_on_notes)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
       tasks_json = ?, tags_json = ?, operators_json = ?, show_tags_on_notes = ?, updated_at = CURRENT_TIMESTAMP`,
      [
        req.user_id,
        JSON.stringify(tasks || []),
        JSON.stringify(tags || []),
        JSON.stringify(operators || []),
        show_tags_on_notes ? 1 : 0,
        JSON.stringify(tasks || []),
        JSON.stringify(tags || []),
        JSON.stringify(operators || []),
        show_tags_on_notes ? 1 : 0,
      ]
    );
    console.log('Data saved for user_id:', req.user_id);
    res.json({ message: 'Data saved' });
  } catch (error) {
    console.error('MySQL error in POST /user-data:', error.message);
    res.status(500).json({ message: 'Server error', details: error.message });
  }
});

// server/index.js Updates
// Add these new endpoints after existing routes

// POST /share-task: Share a task with another user
app.post('/share-task', authenticate, async (req, res) => {
  const { task_id, shared_with_email } = req.body;
  console.log('POST /share-task called for user_id:', req.user_id, 'Data:', { task_id, shared_with_email });

  if (!task_id || !shared_with_email) {
    console.log('Missing task_id or shared_with_email');
    return res.status(400).json({ message: 'Task ID and shared user email are required' });
  }

  try {
    // Find the user to share with
    const [userRows] = await pool.query('SELECT id FROM users WHERE email = ?', [shared_with_email]);
    if (userRows.length === 0) {
      console.log('User not found:', shared_with_email);
      return res.status(404).json({ message: 'User not found' });
    }
    const shared_with_user_id = userRows[0].id;

    // Verify the task belongs to the owner
    const [userDataRows] = await pool.query('SELECT tasks_json FROM user_data WHERE user_id = ?', [req.user_id]);
    if (userDataRows.length === 0) {
      console.log('No data found for user_id:', req.user_id);
      return res.status(404).json({ message: 'User data not found' });
    }
    const tasks = JSON.parse(userDataRows[0].tasks_json);
    const task = tasks.find(t => t.id === task_id);
    if (!task) {
      console.log('Task not found:', task_id);
      return res.status(404).json({ message: 'Task not found' });
    }

    // Insert sharing record
    await pool.query(
      'INSERT INTO shared_tasks (task_id, owner_user_id, shared_with_user_id) VALUES (?, ?, ?)',
      [task_id, req.user_id, shared_with_user_id]
    );

    // Update shared user's shared_tasks_json
    const [sharedUserDataRows] = await pool.query('SELECT shared_tasks_json FROM user_data WHERE user_id = ?', [shared_with_user_id]);
    let sharedTasks = [];
    if (sharedUserDataRows.length > 0) {
      sharedTasks = JSON.parse(sharedUserDataRows[0].shared_tasks_json);
    }
    sharedTasks.push({ task_id, owner_user_id: req.user_id });
    await pool.query(
      'INSERT INTO user_data (user_id, shared_tasks_json) VALUES (?, ?) ON DUPLICATE KEY UPDATE shared_tasks_json = ?',
      [shared_with_user_id, JSON.stringify(sharedTasks), JSON.stringify(sharedTasks)]
    );

    console.log('Task shared:', { task_id, owner_user_id: req.user_id, shared_with_user_id });
    res.json({ message: 'Task shared successfully' });
  } catch (error) {
    console.error('Share task error:', error.message);
    res.status(500).json({ message: 'Server error', details: error.message });
  }
});

// GET /shared-tasks: Get tasks shared with the user
app.get('/shared-tasks', authenticate, async (req, res) => {
  console.log('GET /shared-tasks called for user_id:', req.user_id);
  try {
    const [sharedRows] = await pool.query(
      'SELECT st.task_id, st.owner_user_id, u.email as owner_email, ud.tasks_json, ud.tags_json ' +
      'FROM shared_tasks st ' +
      'JOIN users u ON st.owner_user_id = u.id ' +
      'JOIN user_data ud ON st.owner_user_id = ud.user_id ' +
      'WHERE st.shared_with_user_id = ?',
      [req.user_id]
    );

    const sharedTasks = sharedRows.map(row => {
      const tasks = JSON.parse(row.tasks_json);
      const task = tasks.find(t => t.id === Number(row.task_id));
      return task ? {
        ...task,
        owner_user_id: row.owner_user_id,
        owner_email: row.owner_email,
        owner_tags: JSON.parse(row.tags_json) // Include owner's tags
      } : null;
    }).filter(task => task !== null);

    console.log('Fetched shared tasks for user_id:', req.user_id, sharedTasks);
    res.json({ sharedTasks });
  } catch (error) {
    console.error('Get shared tasks error:', error.message);
    res.status(500).json({ message: 'Server error', details: error.message });
  }
});

// POST /update-shared-task: Update a shared task
app.post('/update-shared-task', authenticate, async (req, res) => {
  const { task_id, owner_user_id, updates } = req.body;
  console.log('POST /update-shared-task called for user_id:', req.user_id, 'Data:', { task_id, owner_user_id, updates });

  if (!task_id || !owner_user_id || !updates) {
    console.log('Missing required fields');
    return res.status(400).json({ message: 'Task ID, owner user ID, and updates are required' });
  }

  try {
    // Verify the user has access to the shared task
    const [shareRows] = await pool.query(
      'SELECT * FROM shared_tasks WHERE task_id = ? AND owner_user_id = ? AND shared_with_user_id = ?',
      [task_id, owner_user_id, req.user_id]
    );
    if (shareRows.length === 0) {
      console.log('No sharing record found for:', { task_id, owner_user_id, shared_with_user_id: req.user_id });
      return res.status(403).json({ message: 'Not authorized to update this task' });
    }

    // Update the task in the owner's user_data
    const [ownerDataRows] = await pool.query('SELECT tasks_json FROM user_data WHERE user_id = ?', [owner_user_id]);
    if (ownerDataRows.length === 0) {
      console.log('Owner data not found:', owner_user_id);
      return res.status(404).json({ message: 'Owner data not found' });
    }
    let tasks = JSON.parse(ownerDataRows[0].tasks_json);
    const taskIndex = tasks.findIndex(t => t.id === task_id);
    if (taskIndex === -1) {
      console.log('Task not found:', task_id);
      return res.status(404).json({ message: 'Task not found' });
    }

    tasks[taskIndex] = { ...tasks[taskIndex], ...updates, tags: (updates.tags || []).map(String), operatedBy: updates.operatedBy || [] };
    await pool.query(
      'UPDATE user_data SET tasks_json = ? WHERE user_id = ?',
      [JSON.stringify(tasks), owner_user_id]
    );

    console.log('Shared task updated:', { task_id, owner_user_id });
    res.json({ message: 'Shared task updated successfully' });
  } catch (error) {
    console.error('Update shared task error:', error.message);
    res.status(500).json({ message: 'Server error', details: error.message });
  }
});

// POST /revoke-share: Revoke sharing of a task with a specific user
app.post('/revoke-share', authenticate, async (req, res) => {
  const { task_id, shared_with_user_id } = req.body;
  console.log('POST /revoke-share called for user_id:', req.user_id, 'Data:', { task_id, shared_with_user_id });

  if (!task_id || !shared_with_user_id) {
    console.log('Missing task_id or shared_with_user_id');
    return res.status(400).json({ message: 'Task ID and shared user ID are required' });
  }

  try {
    // Verify the task belongs to the owner
    const [userDataRows] = await pool.query('SELECT tasks_json FROM user_data WHERE user_id = ?', [req.user_id]);
    if (userDataRows.length === 0) {
      console.log('No data found for user_id:', req.user_id);
      return res.status(404).json({ message: 'User data not found' });
    }
    const tasks = JSON.parse(userDataRows[0].tasks_json);
    const task = tasks.find(t => t.id === Number(task_id));
    if (!task) {
      console.log('Task not found:', task_id);
      return res.status(404).json({ message: 'Task not found' });
    }

    // Delete the sharing record
    const [result] = await pool.query(
      'DELETE FROM shared_tasks WHERE task_id = ? AND owner_user_id = ? AND shared_with_user_id = ?',
      [task_id, req.user_id, shared_with_user_id]
    );

    if (result.affectedRows === 0) {
      console.log('No sharing record found for:', { task_id, owner_user_id: req.user_id, shared_with_user_id });
      return res.status(404).json({ message: 'Sharing record not found' });
    }

    // Update shared user's shared_tasks_json
    const [sharedUserDataRows] = await pool.query('SELECT shared_tasks_json FROM user_data WHERE user_id = ?', [shared_with_user_id]);
    if (sharedUserDataRows.length > 0) {
      let sharedTasks = JSON.parse(sharedUserDataRows[0].shared_tasks_json);
      sharedTasks = sharedTasks.filter(st => !(st.task_id === Number(task_id) && st.owner_user_id === req.user_id));
      await pool.query(
        'UPDATE user_data SET shared_tasks_json = ? WHERE user_id = ?',
        [JSON.stringify(sharedTasks), shared_with_user_id]
      );
    }

    console.log('Task sharing revoked:', { task_id, owner_user_id: req.user_id, shared_with_user_id });
    res.json({ message: 'Task sharing revoked successfully' });
  } catch (error) {
    console.error('Revoke share error:', error.message);
    res.status(500).json({ message: 'Server error', details: error.message });
  }
});

// GET /shared-users: Get list of users a task is shared with
app.get('/shared-users/:task_id', authenticate, async (req, res) => {
  const { task_id } = req.params;
  console.log('GET /shared-users called for user_id:', req.user_id, 'task_id:', task_id);

  try {
    // Verify the task belongs to the owner
    const [userDataRows] = await pool.query('SELECT tasks_json FROM user_data WHERE user_id = ?', [req.user_id]);
    if (userDataRows.length === 0) {
      console.log('No data found for user_id:', req.user_id);
      return res.status(404).json({ message: 'User data not found' });
    }
    const tasks = JSON.parse(userDataRows[0].tasks_json);
    const task = tasks.find(t => t.id === Number(task_id));
    if (!task) {
      console.log('Task not found:', task_id);
      return res.status(404).json({ message: 'Task not found' });
    }

    // Fetch shared users
    const [sharedRows] = await pool.query(
      'SELECT u.id, u.email FROM shared_tasks st JOIN users u ON st.shared_with_user_id = u.id WHERE st.task_id = ? AND st.owner_user_id = ?',
      [task_id, req.user_id]
    );

    console.log('Fetched shared users for task_id:', task_id, sharedRows);
    res.json({ sharedUsers: sharedRows });
  } catch (error) {
    console.error('Get shared users error:', error.message);
    res.status(500).json({ message: 'Server error', details: error.message });
  }
});
// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  console.log('Received forgot password request:', { email });
    console.log(process.env.EMAIL_USER, process.env.EMAIL_PASS);
    

  if (!email) {
    console.log('Missing email');
    return res.status(400).json({ error: 'Email is required' });
  }
  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      console.log('Email not found:', email);
      return res.status(404).json({ error: 'Email not found' });
    }
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hour
    await pool.execute(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?',
      [resetToken, expires, email]
    );
    console.log('Reset token generated for:', email, 'Token:', resetToken);
    const resetUrl = `${process.env.APP_URL}/auth?token=${resetToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      html: `<p>Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.</p>`
    });
    console.log('Reset email sent to:', email);
    res.json({ message: 'Password reset link sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Reset Password Route
app.post('/reset-password', async (req, res) => {
  const { token, newPassword, confirmNewPassword } = req.body;
  console.log('Received reset password request:', { token, newPassword });
  if (!token || !newPassword || !confirmNewPassword) {
    console.log('Missing required fields');
    return res.status(400).json({ error: 'Token, new password, and confirm password are required' });
  }
  if (newPassword !== confirmNewPassword) {
    console.log('Passwords do not match');
    return res.status(400).json({ error: 'Passwords do not match' });
  }
  if (newPassword.length < 7) {
    console.log('Password too short');
    return res.status(400).json({ error: 'Password must be at least 7 characters long' });
  }
  if (!/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword) || !/[^a-zA-Z0-9]/.test(newPassword)) {
    console.log('Password does not meet complexity requirements');
    return res.status(400).json({ error: 'Password must contain letters, numbers, and special characters' });
  }
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > NOW()',
      [token]
    );
    if (rows.length === 0) {
      console.log('Invalid or expired token:', token);
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.execute(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE reset_token = ?',
      [hashedPassword, token]
    );
    console.log('Password reset successful for token:', token);
    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

app.get('/test', (req, res) => {
  res.json({ message: 'Server is running' });
});

app.get('/env', (req, res) => {
  res.json({
    DB_HOST: process.env.DB_HOST,
    DB_USER: process.env.DB_USER,
    DB_PASSWORD: process.env.DB_PASSWORD,
    DB_NAME: process.env.DB_NAME,
    JWT_SECRET: process.env.JWT_SECRET,
    PORT: process.env.PORT
  });
});

app.post('/signup', async (req, res) => {
  console.log('Received signup request:', req.body);
  const { email, password, firstName, lastName, phone } = req.body;
  if (!email || !password || !firstName || !lastName || !phone) {
    console.log('Missing required fields');
    return res.status(400).json({ error: 'Email, password, first name, last name, and phone are required' });
  }
  if (password.length < 7) {
    console.log('Password too short');
    return res.status(400).json({ error: 'Password must be at least 7 characters long' });
  }
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password) || !/[^a-zA-Z0-9]/.test(password)) {
    console.log('Password does not meet complexity requirements');
    return res.status(400).json({ error: 'Password must contain letters, numbers, and special characters' });
  }
  try {
    console.log('Connecting to MySQL...');
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Inserting user:', { email, firstName, lastName, phone, hashedPassword });
    const [result] = await pool.execute(
      'INSERT INTO users (email, password, first_name, last_name, phone) VALUES (?, ?, ?, ?, ?)',
      [email, hashedPassword, firstName, lastName, phone]
    );
    console.log('Insert result:', result);
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Signup error:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(409).json({ error: 'Email already exists' });
    } else {
      res.status(500).json({ error: 'Server error', details: error.message });
    }
  }
});

app.post('/login', async (req, res) => {
  console.log('Received login request:', req.body);
  const { email, password } = req.body;
  if (!email || !password) {
    console.log('Missing email or password');
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    console.log('Querying user:', email);
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      console.log('User not found');
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const user = rows[0];
    console.log('Verifying password for user:', user.email);
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Password mismatch');
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: '1h'
    });
    console.log('Login successful, token generated',token);
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});