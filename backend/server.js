const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const fs = require('fs');
const sanitizeHtml = require('sanitize-html');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL, // Use FRONTEND_URL from .env
  credentials: true
}));

// Validate environment variables
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'DB_PORT', 'JWT_SECRET', 'FRONTEND_URL'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing environment variable: ${envVar}`);
    process.exit(1);
  }
}
// Load CA certificate
let caCert;
try {
  if (fs.existsSync('./ca-cert.pem')) {
    caCert = fs.readFileSync('./ca-cert.pem', 'utf8');
    console.log('Loaded CA certificate from ca-cert.pem');
  } else if (process.env.DB_CA_CERT) {
    caCert = process.env.DB_CA_CERT.replace(/\\n/g, '\n');
    console.warn('ca-cert.pem not found, using DB_CA_CERT from .env');
  } else {
    throw new Error('Neither ca-cert.pem nor DB_CA_CERT in .env found. Please provide the CA certificate.');
  }
  if (process.env.DEBUG_SSL === 'true') {
    console.log('CA Certificate (first 50 chars):', caCert.slice(0, 50));
  }
} catch (error) {
  console.error('Failed to load CA certificate:', error.message);
  process.exit(1);
}

// MySQL connection configuration for Aiven.io
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: parseInt(process.env.DB_PORT),
  ssl: {
    rejectUnauthorized: process.env.DEBUG_SSL === 'true' ? false : true,
    ca: caCert
  },
  connectTimeout: 15000,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

// Database connection pool
const pool = mysql.createPool(dbConfig);

// Test database connection with retry logic
async function testConnection(retries = 5, delay = 3000) {
  for (let i = 0; i < retries; i++) {
    try {
      const connection = await pool.getConnection();
      console.log('Successfully connected to Aiven.io MySQL database');
      connection.release();
      return true;
    } catch (error) {
      console.error(`Connection attempt ${i + 1} failed:`, {
        message: error.message,
        code: error.code,
        stack: error.stack
      });
      if (i < retries - 1) {
        console.log(`Retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  throw new Error('Failed to connect to database after retries');
}

// Input sanitization
const sanitizeInput = (input) => {
  return sanitizeHtml(input, {
    allowedTags: [],
    allowedAttributes: {}
  });
};

// Middleware to verify JWT
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('JWT verification error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(401).json({ error: error.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token' });
  }
};

// Middleware to verify admin-only access
const adminMiddleware = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// User registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    const sanitizedName = sanitizeInput(name);
    const sanitizedEmail = sanitizeInput(email);
    const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
    if (existingUsers.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    await pool.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [sanitizedName, sanitizedEmail, hashedPointer]
    );
    res.status(201).json({ message: 'Registration successful' });
  } catch (error) {
    console.error('Registration error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin registration endpoint
app.post('/api/admin/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (role !== 'admin' && role !== 'user') {
      return res.status(400).json({ error: 'Invalid role' });
    }
    const sanitizedName = sanitizeInput(name);
    const sanitizedEmail = sanitizeInput(email);
    const [existingAdmins] = await pool.query('SELECT * FROM admins WHERE email = ?', [sanitizedEmail]);
    if (existingAdmins.length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    await pool.query(
      'INSERT INTO admins (name, email, password) VALUES (?, ?, ?)',
      [sanitizedName, sanitizedEmail, hashedPassword]
    );
    res.status(201).json({ message: 'Admin registration successful' });
  } catch (error) {
    console.error('Admin registration error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// User login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const sanitizedEmail = sanitizeInput(email);
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail]);
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user.id, isAdmin: false }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: user.id, isAdmin: false }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ 
      token, 
      refreshToken, 
      user: { id: user.id, name: user.name, email: user.email, role: 'user' }
    });
  } catch (error) {
    console.error('Login error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const sanitizedEmail = sanitizeInput(email);
    const [admins] = await pool.query('SELECT * FROM admins WHERE email = ?', [sanitizedEmail]);
    if (admins.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const admin = admins[0];
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: admin.id, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: admin.id, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ 
      token, 
      refreshToken, 
      user: { id: admin.id, name: admin.name, email: admin.email, role: 'admin' }
    });
  } catch (error) {
    console.error('Admin login error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Refresh token endpoint
app.post('/api/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const table = decoded.isAdmin ? 'admins' : 'users';
    const [records] = await pool.query(`SELECT id FROM ${table} WHERE id = ?`, [decoded.userId]);
    if (records.length === 0) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    const newToken = jwt.sign({ userId: decoded.userId, isAdmin: decoded.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token: newToken });
  } catch (error) {
    console.error('Refresh token error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// Protected route
app.get('/api/protected', authMiddleware, async (req, res) => {
  try {
    const table = req.user.isAdmin ? 'admins' : 'users';
    const [records] = await pool.query(`SELECT id, name, email FROM ${table} WHERE id = ?`, [req.user.userId]);
    if (records.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = records[0];
    user.role = req.user.isAdmin ? 'admin' : 'user';
    res.json(user);
  } catch (error) {
    console.error('Protected route error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch all users (admin-only)
app.get('/api/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, name, email, created_at FROM users ORDER BY created_at DESC');
    res.json(users);
  } catch (error) {
    console.error('Fetch users error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch single user (admin-only)
app.get('/api/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [users] = await pool.query('SELECT id, name, email, created_at FROM users WHERE id = ?', [req.params.id]);
    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(users[0]);
  } catch (error) {
    console.error('Fetch user error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Update user (admin-only)
app.patch('/api/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    const sanitizedName = sanitizeInput(name);
    const sanitizedEmail = sanitizeInput(email);
    let query = 'UPDATE users SET name = ?, email = ?';
    const params = [sanitizedName, sanitizedEmail];
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
      }
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      query += ', password = ?';
      params.push(hashedPassword);
    }
    query += ' WHERE id = ?';
    params.push(req.params.id);
    const [result] = await pool.query(query, params);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User updated successfully' });
  } catch (error) {
    console.error('Update user error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete user (admin-only)
app.delete('/api/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch single contact message (admin-only)
app.get('/api/contact/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [messages] = await pool.query('SELECT id, name, email, message, created_at FROM contact_messages WHERE id = ?', [req.params.id]);
    if (messages.length === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    res.json(messages[0]);
  } catch (error) {
    console.error('Fetch contact message error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Update contact message (admin-only)
app.patch('/api/contact/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (message.length < 10) {
      return res.status(400).json({ error: 'Message must be at least 10 characters' });
    }
    const sanitizedData = {
      name: sanitizeInput(name),
      email: sanitizeInput(email),
      message: sanitizeInput(message)
    };
    const [result] = await pool.query(
      'UPDATE contact_messages SET name = ?, email = ?, message = ? WHERE id = ?',
      [sanitizedData.name, sanitizedData.email, sanitizedData.message, req.params.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Message not found' });
    }
    res.json({ message: 'Message updated successfully' });
  } catch (error) {
    console.error('Update contact message error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Redirect non-admin /admin requests
app.get('/admin', authMiddleware, (req, res) => {
  if (!req.user.isAdmin) {
    return res.redirect('/');
  }
  res.json({ message: 'Admin page' });
});

// Existing endpoints (posts, tech news, trending tech, contact) remain unchanged
// Create post endpoint
app.post('/api/posts', authMiddleware, async (req, res) => {
  try {
    const { title, excerpt, content, category, image, userId } = req.body;
    if (!title || !excerpt || !content || !category || !userId) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    if (userId !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const sanitizedData = {
      title: sanitizeInput(title),
      excerpt: sanitizeInput(excerpt),
      content: sanitizeInput(content),
      category: sanitizeInput(category),
      image: image ? sanitizeInput(image) : null
    };
    await pool.query(
      'INSERT INTO posts (title, excerpt, content, category, image, user_id) VALUES (?, ?, ?, ?, ?, ?)',
      [sanitizedData.title, sanitizedData.excerpt, sanitizedData.content, sanitizedData.category, sanitizedData.image, userId]
    );
    res.status(201).json({ message: 'Post created successfully' });
  } catch (error) {
    console.error('Post creation error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Update post endpoint
app.patch('/api/posts/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, excerpt, content, category, image, userId } = req.body;
    if (!title || !excerpt || !content || !category || !userId) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    if (userId !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const [posts] = await pool.query('SELECT user_id FROM posts WHERE id = ?', [id]);
    if (posts.length === 0 || posts[0].user_id !== userId) {
      return res.status(403).json({ error: 'Not authorized to edit this post' });
    }
    const sanitizedData = {
      title: sanitizeInput(title),
      excerpt: sanitizeInput(excerpt),
      content: sanitizeInput(content),
      category: sanitizeInput(category),
      image: image ? sanitizeInput(image) : null
    };
    await pool.query(
      'UPDATE posts SET title = ?, excerpt = ?, content = ?, category = ?, image = ? WHERE id = ?',
      [sanitizedData.title, sanitizedData.excerpt, sanitizedData.content, sanitizedData.category, sanitizedData.image, id]
    );
    res.json({ message: 'Post updated successfully' });
  } catch (error) {
    console.error('Post update error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete post endpoint
app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const [posts] = await pool.query('SELECT user_id FROM posts WHERE id = ?', [id]);
    if (posts.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }
    if (posts[0].user_id !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to delete this post' });
    }
    await pool.query('DELETE FROM posts WHERE id = ?', [id]);
    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error('Post deletion error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch all posts with search and optional userId filter
app.get('/api/posts', async (req, res) => {
  try {
    const search = req.query.search ? `%${sanitizeInput(req.query.search)}%` : '%';
    const userId = req.query.userId ? parseInt(req.query.userId) : null;
    let query = `
      SELECT p.id, p.title, p.excerpt, p.content, p.category, p.image, p.created_at, p.user_id, u.name as author
      FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE (p.title LIKE ? OR p.excerpt LIKE ?)
    `;
    const params = [search, search];
    if (userId) {
      query += ' AND p.user_id = ?';
      params.push(userId);
    }
    query += ' ORDER BY p.created_at DESC';
    const [posts] = await pool.query(query, params);
    res.json(posts);
  } catch (error) {
    console.error('Fetch posts error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch single post
app.get('/api/posts/:id', async (req, res) => {
  try {
    const [posts] = await pool.query(`
      SELECT p.id, p.title, p.excerpt, p.content, p.category, p.image, p.created_at, u.name as author
      FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE p.id = ?
    `, [req.params.id]);
    if (posts.length === 0) {
      return res.status(404).json({ error: 'Post not found' });
    }
    res.json(posts[0]);
  } catch (error) {
    console.error('Fetch post error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Create tech news endpoint
app.post('/api/news', authMiddleware, async (req, res) => {
  try {
    const { title, summary, source, userId } = req.body;
    if (!title || !summary || !source || !userId) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    if (userId !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const sanitizedData = {
      title: sanitizeInput(title),
      summary: sanitizeInput(summary),
      source: sanitizeInput(source)
    };
    await pool.query(
      'INSERT INTO tech_news (title, summary, source, user_id) VALUES (?, ?, ?, ?)',
      [sanitizedData.title, sanitizedData.summary, sanitizedData.source, userId]
    );
    res.status(201).json({ message: 'Tech news created successfully' });
  } catch (error) {
    console.error('Tech news creation error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Update tech news endpoint
app.patch('/api/news/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, summary, source, userId } = req.body;
    if (!title || !summary || !source || !userId) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    if (userId !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const [news] = await pool.query('SELECT user_id FROM tech_news WHERE id = ?', [id]);
    if (news.length === 0 || news[0].user_id !== userId) {
      return res.status(403).json({ error: 'Not authorized to edit this news item' });
    }
    const sanitizedData = {
      title: sanitizeInput(title),
      summary: sanitizeInput(summary),
      source: sanitizeInput(source)
    };
    await pool.query(
      'UPDATE tech_news SET title = ?, summary = ?, source = ? WHERE id = ?',
      [sanitizedData.title, sanitizedData.summary, sanitizedData.source, id]
    );
    res.json({ message: 'Tech news updated successfully' });
  } catch (error) {
    console.error('Tech news update error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete tech news endpoint
app.delete('/api/news/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const [news] = await pool.query('SELECT user_id FROM tech_news WHERE id = ?', [id]);
    if (news.length === 0) {
      return res.status(404).json({ error: 'News item not found' });
    }
    if (news[0].user_id !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to delete this news item' });
    }
    await pool.query('DELETE FROM tech_news WHERE id = ?', [id]);
    res.json({ message: 'News item deleted successfully' });
  } catch (error) {
    console.error('News deletion error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch all tech news with search and optional userId filter
app.get('/api/news', async (req, res) => {
  try {
    const search = req.query.search ? `%${sanitizeInput(req.query.search)}%` : '%';
    const userId = req.query.userId ? parseInt(req.query.userId) : null;
    let query = `
      SELECT id, title, summary, source, created_at, user_id
      FROM tech_news
      WHERE title LIKE ? OR summary LIKE ?
    `;
    const params = [search, search];
    if (userId) {
      query += ' AND user_id = ?';
      params.push(userId);
    }
    query += ' ORDER BY created_at DESC';
    const [news] = await pool.query(query, params);
    res.json(news);
  } catch (error) {
    console.error('Fetch tech news error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Create trending tech endpoint
app.post('/api/trending', authMiddleware, async (req, res) => {
  try {
    const { title, summary, source, userId } = req.body;
    if (!title || !summary || !source || !userId) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    if (userId !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const sanitizedData = {
      title: sanitizeInput(title),
      summary: sanitizeInput(summary),
      source: sanitizeInput(source)
    };
    await pool.query(
      'INSERT INTO trending_tech (title, summary, source, user_id) VALUES (?, ?, ?, ?)',
      [sanitizedData.title, sanitizedData.summary, sanitizedData.source, userId]
    );
    res.status(201).json({ message: 'Trending tech created successfully' });
  } catch (error) {
    console.error('Trending tech creation error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Update trending tech endpoint
app.patch('/api/trending/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, summary, source, userId } = req.body;
    if (!title || !summary || !source || !userId) {
      return res.status(400).json({ error: 'All required fields must be provided' });
    }
    if (userId !== req.user.userId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const [trending] = await pool.query('SELECT user_id FROM trending_tech WHERE id = ?', [id]);
    if (trending.length === 0 || trending[0].user_id !== userId) {
      return res.status(403).json({ error: 'Not authorized to edit this trending item' });
    }
    const sanitizedData = {
      title: sanitizeInput(title),
      summary: sanitizeInput(summary),
      source: sanitizeInput(source)
    };
    await pool.query(
      'UPDATE trending_tech SET title = ?, summary = ?, source = ? WHERE id = ?',
      [sanitizedData.title, sanitizedData.summary, sanitizedData.source, id]
    );
    res.json({ message: 'Trending tech updated successfully' });
  } catch (error) {
    console.error('Trending tech update error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete trending tech endpoint
app.delete('/api/trending/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const [trending] = await pool.query('SELECT user_id FROM trending_tech WHERE id = ?', [id]);
    if (trending.length === 0) {
      return res.status(404).json({ error: 'Trending item not found' });
    }
    if (trending[0].user_id !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to delete this trending item' });
    }
    await pool.query('DELETE FROM trending_tech WHERE id = ?', [id]);
    res.json({ message: 'Trending item deleted successfully' });
  } catch (error) {
    console.error('Trending deletion error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch all trending tech with search and optional userId filter
app.get('/api/trending', async (req, res) => {
  try {
    const search = req.query.search ? `%${sanitizeInput(req.query.search)}%` : '%';
    const userId = req.query.userId ? parseInt(req.query.userId) : null;
    let query = `
      SELECT id, title, summary, source, created_at, user_id
      FROM trending_tech
      WHERE title LIKE ? OR summary LIKE ?
    `;
    const params = [search, search];
    if (userId) {
      query += ' AND user_id = ?';
      params.push(userId);
    }
    query += ' ORDER BY created_at DESC';
    const [trending] = await pool.query(query, params);
    res.json(trending);
  } catch (error) {
    console.error('Fetch trending tech error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Create contact message endpoint
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (message.length < 10) {
      return res.status(400).json({ error: 'Message must be at least 10 characters' });
    }
    const sanitizedData = {
      name: sanitizeInput(name),
      email: sanitizeInput(email),
      message: sanitizeInput(message)
    };
    await pool.query(
      'INSERT INTO contact_messages (name, email, message) VALUES (?, ?, ?)',
      [sanitizedData.name, sanitizedData.email, sanitizedData.message]
    );
    res.status(201).json({ message: 'Message sent successfully' });
  } catch (error) {
    console.error('Contact submission error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Fetch all contact messages (admin-only)
app.get('/api/contact', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [messages] = await pool.query('SELECT id, name, email, message, created_at FROM contact_messages ORDER BY created_at DESC');
    res.json(messages);
  } catch (error) {
    console.error('Fetch contact messages error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    connection.release();
    res.status(200).json({ status: 'healthy', database: 'connected' });
  } catch (error) {
    console.error('Health check error:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({ status: 'unhealthy', database: 'disconnected' });
  }
});

// Create database tables
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        excerpt TEXT NOT NULL,
        content TEXT NOT NULL,
        category VARCHAR(100) NOT NULL,
        image VARCHAR(255),
        user_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tech_news (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        summary TEXT NOT NULL,
        source VARCHAR(255) NOT NULL,
        user_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS trending_tech (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        summary TEXT NOT NULL,
        source VARCHAR(255) NOT NULL,
        user_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS contact_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', {
      message: error.message,
      stack: error.stack
    });
    throw error;
  }
}

// Start server
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, async () => {
  try {
    await testConnection();
    await initializeDatabase();
    console.log(`Server running on port ${PORT}`);
  } catch (error) {
    console.error('Failed to start server:', {
      message: error.message,
      stack: error.stack
    });
    process.exit(1);
  }
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received. Closing server...');
  server.close(async () => {
    console.log('Server closed');
    try {
      await pool.end();
      console.log('Database connections closed');
      process.exit(0);
    } catch (error) {
      console.error('Error closing database connections:', {
        message: error.message,
        stack: error.stack
      });
      process.exit(1);
    }
  });
});
