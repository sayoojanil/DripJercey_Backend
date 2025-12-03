import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { Resend } from "resend";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || "local_dev_secret_2025";
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const runningOnVercel = process.env.VERCEL === "1";

// Initialize Resend
const resend = new Resend(process.env.RESEND_API_KEY);

// ------------------ RATE LIMITER ------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { message: "Too many login attempts. Try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ------------------ SCHEMAS ------------------
const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true },
    password: String,
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

const profileSchema = new mongoose.Schema({
  userId: String,
  name: String,
  email: String,
  phone: String,
  address: String,
});
const Profile = mongoose.model("Profile", profileSchema);

const cartSchema = new mongoose.Schema({
  userId: String,
  productId: String,
  quantity: Number,
  size: String,
});
const Cart = mongoose.model("Cart", cartSchema);

const wishlistSchema = new mongoose.Schema({
  productName: String,
  userId: String,
  productId: String,
  date: Date,
});
const Wishlist = mongoose.model("Wishlist", wishlistSchema);

const orderSchema = new mongoose.Schema({
  userId: String,
  name: String,
  category: String,
  items: Array,
  total: Number,
  date: Date,
});
const Order = mongoose.model("Order", orderSchema);

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true },
    price: { type: Number, required: true },
    stockAvailable: { type: Number, required: true },
    oldPrice: { type: Number, required: true },
    imageUrl: { type: [String], required: true },
    featured: Boolean,
    trending: Boolean,
  },
  { timestamps: true }
);
const Product = mongoose.model("Product", productSchema);

// ------------------ CONNECT TO MONGODB ------------------
let cachedConnection = null;
let cachedPromise = null;

async function connectDB() {
  if (cachedConnection) return cachedConnection;

  if (!MONGO_URI) {
    console.error("MONGO_URI environment variable is not set.");
    if (!runningOnVercel) process.exit(1);
    throw new Error("MONGO_URI not set");
  }

  if (!cachedPromise) {
    cachedPromise = mongoose.connect(MONGO_URI).then(() => {
      console.log("MongoDB connected successfully");
      cachedConnection = mongoose.connection;
      return cachedConnection;
    });
  }
  try {
    return await cachedPromise;
  } catch (err) {
    console.error("MongoDB connection error:", err);
    cachedPromise = null;
    cachedConnection = null;
    if (!runningOnVercel) process.exit(1);
    throw err;
  }
}
connectDB().catch(() => {
  // connection errors already logged in connectDB; swallow here to avoid unhandled rejection
});

// ------------------ AUTH MIDDLEWARE ------------------
function authMiddleware(req, res, next) {
  const bearer = req.headers.authorization;
  if (!bearer) return res.status(401).json({ message: "No token" });
  const token = bearer.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// ------------------ AUTH ROUTES ------------------

// SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ message: "Missing fields" });
    }
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "Email already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword });
    await Profile.create({ userId: user._id, name, email });

    const token = jwt.sign({ id: user._id, email }, JWT_SECRET);
    return res.json({ token, user: { id: user._id, name, email } });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ message: "Email already exists" });
    }
    console.error("SIGNUP ERROR:", err);
    return res.status(500).json({ message: "Signup failed" });
  }
});

// LOGIN (Rate Limited)
app.post("/loginWithEmail", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email }, JWT_SECRET);
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Login failed" });
  }
});

// FORGOT PASSWORD
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email required" });

    const user = await User.findOne({ email });
    if (!user) {
       console.log("email send to{{email}}");
      return res.json({ message: "Check your email for reset link (if registered)" });
     
    }

    const resetToken = jwt.sign(
      { id: user._id, purpose: "password-reset" },
      JWT_SECRET,
      { expiresIn: "15m" }
    );

    const resetLink = `${CLIENT_URL}/reset-password/${resetToken}`;

    // If RESEND_API_KEY is not set, avoid calling Resend and return the link in the response (for dev)
    if (!process.env.RESEND_API_KEY) {
      console.warn("RESEND_API_KEY not set — returning reset link in response for development.");
      console.log("Reset link (dev):", resetLink);
      return res.json({ message: "Reset link generated (dev)", resetLink });
    }

    await resend.emails.send({
      from: "onboarding@resend.dev", // use a valid sender
      to: email,
      subject: "Password Reset - Drip Jersey",
      html: `
        <h2>Reset Your Password</h2>
        <p>Click here: <a href="${resetLink}">Reset Password</a></p>
        <p>Or copy: ${resetLink}</p>
        <p>Expires in 15 minutes.</p>
      `,
    });

    console.log("Reset link (for testing):", resetLink);
    res.json({ message: "Reset link sent! Check spam + console." });
  } catch (err) {
    console.error("Resend error:", err);
    res.status(500).json({ message: "Failed", error: err && err.message ? err.message : String(err) });
  }
});

// RESET PASSWORD
app.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password || password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.purpose !== "password-reset") {
      return res.status(400).json({ message: "Invalid reset token" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.findByIdAndUpdate(decoded.id, { password: hashedPassword });

    res.json({ message: "Password reset successful" });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(400).json({ message: "Reset link has expired" });
    }
    if (err.name === "JsonWebTokenError") {
      return res.status(400).json({ message: "Invalid or corrupted reset link" });
    }
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Password reset failed" });
  }
});

// ------------------ USER ROUTES ------------------
app.get("/auth/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("name email");
    if (!user) return res.status(404).json({ message: "User not found" });
    const profile = await Profile.findOne({ userId: req.user.id });
    res.json({
      ...user.toObject(),
      phone: profile?.phone || "",
      address: profile?.address || "",
    });
  } catch {
    res.status(500).json({ message: "Failed to fetch user" });
  }
});

// ------------------ PRODUCTS ------------------
app.post("/products", async (req, res) => {
  try {
    const saved = await Product.create(req.body);
    res.json(saved);
  } catch (e) {
    res.status(500).json({ message: "Product save failed" });
  }
});

app.get("/products", async (req, res) => {
  try {
    const { category, minPrice, maxPrice, sort } = req.query;
    const filter = {};
    if (category) filter.category = category;
    if (minPrice) filter.price = { ...filter.price, $gte: Number(minPrice) };
    if (maxPrice) filter.price = { ...filter.price, $lte: Number(maxPrice) };

    let query = Product.find(filter);
    if (sort === "asc") query = query.sort({ price: 1 });
    if (sort === "desc") query = query.sort({ price: -1 });

    res.json(await query.exec());
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch products" });
  }
});

app.get("/products/featured", async (req, res) => {
  res.json(await Product.find({ featured: true }));
});

app.get("/products/trending", async (req, res) => {
  res.json(await Product.find({ trending: true }));
});

app.get("/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Not found" });
    res.json(product);
  } catch {
    res.status(500).json({ message: "Failed" });
  }
});

// ------------------ CART, WISHLIST, ORDERS, PROFILE ------------------
// (All your existing routes remain unchanged)
app.get("/cart", authMiddleware, async (req, res) => {
  res.json(await Cart.find({ userId: req.user.id }));
});
app.post("/cart", authMiddleware, async (req, res) => {
  const saved = await Cart.create({ userId: req.user.id, ...req.body });
  res.json(saved);
});
app.put("/cart/:id", authMiddleware, async (req, res) => {
  const updated = await Cart.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updated);
});
app.delete("/cart/:id", authMiddleware, async (req, res) => {
  await Cart.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

app.get("/wishlist", authMiddleware, async (req, res) => {
  res.json(await Wishlist.find({ userId: req.user.id }));
});
app.post("/wishlist/:productId", authMiddleware, async (req, res) => {
  await Wishlist.create({ userId: req.user.id, productId: req.params.productId });
  res.json({ message: "Added" });
});
app.delete("/wishlist/:productId", authMiddleware, async (req, res) => {
  await Wishlist.deleteOne({ userId: req.user.id, productId: req.params.productId });
  res.json({ message: "Removed" });
});

app.get("/orders", authMiddleware, async (req, res) => {
  // ... your existing detailed orders logic
});
app.post("/orders", authMiddleware, async (req, res) => {
  const order = await Order.create({ userId: req.user.id, ...req.body, date: new Date() });
  res.json(order);
});

app.get("/admin/orders", async (req, res) => {
  // ... your admin orders logic
});

app.get("/profile", authMiddleware, async (req, res) => {
  res.json(await Profile.findOne({ userId: req.user.id }));
});
app.put("/profile", authMiddleware, async (req, res) => {
  const updated = await Profile.findOneAndUpdate(
    { userId: req.user.id },
    req.body,
    { new: true }
  );
  res.json(updated);
});

// ------------------ HEALTH & ROOT ------------------
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    mongo: mongoose.connection.readyState === 1 ? "connected" : "down",
  });
});

app.get("/", (req, res) => {
  res.send(`Drip Jersey Backend is running!`);
});

// ------------------ START SERVER ------------------
if (!runningOnVercel) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

export default app;