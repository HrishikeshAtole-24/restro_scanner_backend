require('dotenv').config(); // load environment variables from .env
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3009;

app.use(express.json());
app.use(cors());
app.get('', (req, res)=>{
    res.send("server is running")
})
// Create a connection pool to your Neon PostgreSQL database using .env variables
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// JWT secret for signing tokens (set this in your .env file ideally)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ----------------------
// User Authentication
// ----------------------

// Registration endpoint
app.post('/register', async (req, res) => {
  const { username, password, email, role } = req.body;
  try {
    // const hashedPassword = await bcrypt.hash(password, 10);
    const hashedPassword = await bcrypt.hash(password, 12);

    await pool.query(
      'INSERT INTO users (username, password, email, role) VALUES ($1, $2, $3, $4)',
      [username, hashedPassword, email, role || 'customer']
    );
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0)
      return res.status(400).json({ error: 'User not found' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(400).json({ error: 'Incorrect password' });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role},
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout endpoint (for JWT, logout is handled client side)
app.post('/logout', (req, res) => {
  res.json({ message: 'Logout successful' });
});

// ----------------------
// Restaurant Endpoints
// ----------------------

// Create restaurant (only accessible by restaurant_owner or admin)
app.post('/restaurants', authenticateToken, async (req, res) => {
  if (req.user.role !== 'restaurant_owner' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const { name, description, address, phone, email, website } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO restaurants (user_id, name, description, address, phone, email, website) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
      [req.user.id, name, description, address, phone, email, website]
    );
    const restaurantId = result.rows[0].id;

    // Generate a QR code that links to the restaurant's menu
    const qrText = `http://localhost:${port}/menu/${restaurantId}`;
    const qrDataURL = await QRCode.toDataURL(qrText);
    const base64Data = qrDataURL.split(',')[1];
    const qrBuffer = Buffer.from(base64Data, 'base64');

    // Store the QR code in the qr_codes table
    await pool.query(
      'INSERT INTO qr_codes (restaurant_id, qr_code_text, qr_code_blob) VALUES ($1, $2, $3)',
      [restaurantId, qrText, qrBuffer]
    );
    res.status(201).json({ message: 'Restaurant created successfully', restaurantId, qrCode: qrText });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to create restaurant' });
  }
});

// Edit restaurant
app.put('/restaurants/:id', authenticateToken, async (req, res) => {
  const restaurantId = req.params.id;
  const { name, description, address, phone, email, website } = req.body;
  try {
    const result = await pool.query('SELECT * FROM restaurants WHERE id = $1', [restaurantId]);
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Restaurant not found' });
    const restaurant = result.rows[0];
    if (restaurant.user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Access denied' });

    await pool.query(
      'UPDATE restaurants SET name=$1, description=$2, address=$3, phone=$4, email=$5, website=$6 WHERE id=$7',
      [name, description, address, phone, email, website, restaurantId]
    );
    res.json({ message: 'Restaurant updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update restaurant' });
  }
});

// Delete restaurant
app.delete('/restaurants/:id', authenticateToken, async (req, res) => {
  const restaurantId = req.params.id;
  try {
    const result = await pool.query('SELECT * FROM restaurants WHERE id = $1', [restaurantId]);
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Restaurant not found' });
    const restaurant = result.rows[0];
    if (restaurant.user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Access denied' });

    await pool.query('DELETE FROM restaurants WHERE id=$1', [restaurantId]);
    res.json({ message: 'Restaurant deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete restaurant' });
  }
});

// ----------------------
// Category Endpoints
// ----------------------

// Add category to a restaurant
app.post('/restaurants/:restaurantId/categories', authenticateToken, async (req, res) => {
  const restaurantId = req.params.restaurantId;
  const { name, description } = req.body;
  try {
    const result = await pool.query('SELECT * FROM restaurants WHERE id = $1', [restaurantId]);
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Restaurant not found' });
    const restaurant = result.rows[0];
    if (restaurant.user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Access denied' });

    const catResult = await pool.query(
      'INSERT INTO categories (restaurant_id, name, description) VALUES ($1, $2, $3) RETURNING id',
      [restaurantId, name, description]
    );
    res.status(201).json({ message: 'Category added successfully', categoryId: catResult.rows[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to add category' });
  }
});

// Edit category
app.put('/categories/:id', authenticateToken, async (req, res) => {
  const categoryId = req.params.id;
  const { name, description } = req.body;
  try {
    const catResult = await pool.query('SELECT * FROM categories WHERE id = $1', [categoryId]);
    if (catResult.rows.length === 0)
      return res.status(404).json({ error: 'Category not found' });
    const category = catResult.rows[0];

    const restResult = await pool.query('SELECT * FROM restaurants WHERE id = $1', [category.restaurant_id]);
    if (restResult.rows.length === 0)
      return res.status(404).json({ error: 'Restaurant not found' });
    const restaurant = restResult.rows[0];
    if (restaurant.user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Access denied' });

    await pool.query(
      'UPDATE categories SET name=$1, description=$2 WHERE id=$3',
      [name, description, categoryId]
    );
    res.json({ message: 'Category updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update category' });
  }
});

// Delete category
app.delete('/categories/:id', authenticateToken, async (req, res) => {
  const categoryId = req.params.id;
  try {
    const catResult = await pool.query('SELECT * FROM categories WHERE id = $1', [categoryId]);
    if (catResult.rows.length === 0)
      return res.status(404).json({ error: 'Category not found' });
    const category = catResult.rows[0];

    const restResult = await pool.query('SELECT * FROM restaurants WHERE id = $1', [category.restaurant_id]);
    if (restResult.rows.length === 0)
      return res.status(404).json({ error: 'Restaurant not found' });
    const restaurant = restResult.rows[0];
    if (restaurant.user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Access denied' });

    await pool.query('DELETE FROM categories WHERE id=$1', [categoryId]);
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete category' });
  }
});

// ----------------------
// Dish Endpoints
// ----------------------

// Add dish to a category
app.post('/categories/:categoryId/dishes', authenticateToken, async (req, res) => {
  const categoryId = req.params.categoryId;
  const { name, description, price, image_url } = req.body;
  try {
    const catResult = await pool.query('SELECT * FROM categories WHERE id = $1', [categoryId]);
    if (catResult.rows.length === 0)
      return res.status(404).json({ error: 'Category not found' });
    const category = catResult.rows[0];

    const restResult = await pool.query('SELECT * FROM restaurants WHERE id = $1', [category.restaurant_id]);
    if (restResult.rows.length === 0)
      return res.status(404).json({ error: 'Restaurant not found' });
    const restaurant = restResult.rows[0];
    if (restaurant.user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Access denied' });

    const dishResult = await pool.query(
      'INSERT INTO dishes (category_id, name, description, price, image_url) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [categoryId, name, description, price, image_url]
    );
    res.status(201).json({ message: 'Dish added successfully', dishId: dishResult.rows[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to add dish' });
  }
});

// Edit dish
app.put('/dishes/:id', authenticateToken, async (req, res) => {
  const dishId = req.params.id;
  const { name, description, price, image_url } = req.body;
  try {
    const dishResult = await pool.query('SELECT * FROM dishes WHERE id = $1', [dishId]);
    if (dishResult.rows.length === 0)
      return res.status(404).json({ error: 'Dish not found' });
    const dish = dishResult.rows[0];

    const catResult = await pool.query('SELECT * FROM categories WHERE id = $1', [dish.category_id]);
    if (catResult.rows.length === 0)
      return res.status(404).json({ error: 'Category not found' });
    const category = catResult.rows[0];

    const restResult = await pool.query('SELECT * FROM restaurants WHERE id = $1', [category.restaurant_id]);
    if (restResult.rows.length === 0)
      return res.status(404).json({ error: 'Restaurant not found' });
    const restaurant = restResult.rows[0];
    if (restaurant.user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Access denied' });

    await pool.query(
      'UPDATE dishes SET name=$1, description=$2, price=$3, image_url=$4 WHERE id=$5',
      [name, description, price, image_url, dishId]
    );
    res.json({ message: 'Dish updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update dish' });
  }
});

// Delete dish
app.delete('/dishes/:id', authenticateToken, async (req, res) => {
  const dishId = req.params.id;
  try {
    const dishResult = await pool.query('SELECT * FROM dishes WHERE id = $1', [dishId]);
    if (dishResult.rows.length === 0)
      return res.status(404).json({ error: 'Dish not found' });
    const dish = dishResult.rows[0];

    const catResult = await pool.query('SELECT * FROM categories WHERE id = $1', [dish.category_id]);
    if (catResult.rows.length === 0)
      return res.status(404).json({ error: 'Category not found' });
    const category = catResult.rows[0];

    const restResult = await pool.query('SELECT * FROM restaurants WHERE id = $1', [category.restaurant_id]);
    if (restResult.rows.length === 0)
      return res.status(404).json({ error: 'Restaurant not found' });
    const restaurant = restResult.rows[0];
    if (restaurant.user_id !== req.user.id && req.user.role !== 'admin')
      return res.status(403).json({ error: 'Access denied' });

    await pool.query('DELETE FROM dishes WHERE id=$1', [dishId]);
    res.json({ message: 'Dish deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete dish' });
  }
});

// ----------------------
// Menu Display Endpoint
// ----------------------

// Returns the restaurant's menu by listing categories and then the dishes within each category
app.get('/menu/:restaurantId', async (req, res) => {
  const restaurantId = req.params.restaurantId;
  try {
    const catResult = await pool.query('SELECT * FROM categories WHERE restaurant_id = $1', [restaurantId]);
    const menu = [];
    for (const category of catResult.rows) {
      const dishResult = await pool.query('SELECT * FROM dishes WHERE category_id = $1', [category.id]);
      menu.push({
        category: category.name,
        description: category.description,
        dishes: dishResult.rows
      });
    }
    res.json({ menu });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch menu' });
  }
});

// ----------------------
// QR Code Endpoints
// ----------------------

// Get QR code by id in Base64 format
app.get('/qr/:id', async (req, res) => {
  const qrId = req.params.id;
  try {
    const result = await pool.query('SELECT * FROM qr_codes WHERE id = $1', [qrId]);
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'QR code not found' });
    const qr = result.rows[0];
    const base64QRCode = Buffer.from(qr.qr_code_blob, 'binary').toString('base64');
    res.json({ restaurantId: qr.restaurant_id, qrCodeBase64: base64QRCode });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch QR code' });
  }
});
  
// When the QR code is scanned, redirect to the restaurant menu page
app.get('/scan/:qrId', async (req, res) => {
  const qrId = req.params.qrId;
  try {
    const result = await pool.query('SELECT * FROM qr_codes WHERE id = $1', [qrId]);
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'QR code not found' });
    const qr = result.rows[0];
    res.redirect(qr.qr_code_text);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to process QR code scan' });
  }
});

// Get all restaurants created by the logged-in user along with their QR code image
app.get('/restaurants/mine', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT 
       r.id, 
         r.name, 
         r.address, 
         r.phone, 
         r.email, 
         r.website, 
         q.qr_code_blob
       FROM restaurants r
       LEFT JOIN qr_codes q ON r.id = q.restaurant_id
       WHERE r.user_id = $1`,
      [req.user.id]
    );
    
    const restaurantsWithQRCode = result.rows.map(restaurant => {
      let qrCodeImage = null;
      if (restaurant.qr_code_blob) {
        const base64Data = Buffer.from(restaurant.qr_code_blob, 'binary').toString('base64');
        qrCodeImage = `data:image/png;base64,${base64Data}`;
      }
      return {
        name: restaurant.name,
        address: restaurant.address,
        phone: restaurant.phone,
        email: restaurant.email,
        website: restaurant.website,
        qrCode: qrCodeImage
      };
    });
    
    res.json({ restaurants: restaurantsWithQRCode });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to fetch restaurants' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
