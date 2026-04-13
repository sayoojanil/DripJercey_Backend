import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { Resend } from "resend";
import Razorpay from "razorpay";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(cors());

// IMPORTANT: Raw body for Razorpay webhook must be BEFORE express.json()
app.use("/webhook/razorpay", express.raw({ type: "application/json" }));
app.use(express.json());
app.set("json spaces", 2);

const JWT_SECRET = process.env.JWT_SECRET || "local_dev_secret_2025";
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL;
const runningOnVercel = process.env.VERCEL === "1";

// Razorpay
console.log("Razorpay Key ID:", process.env.RAZORPAY_KEY_ID ? `${process.env.RAZORPAY_KEY_ID.substring(0, 8)}...` : "MISSING");
console.log("Razorpay Secret:", process.env.RAZORPAY_KEY_SECRET ? "LOADED" : "MISSING");

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID?.trim(),
  key_secret: process.env.RAZORPAY_KEY_SECRET?.trim(),
});

console.log("Final Razorpay Key ID used:", razorpay.key_id ? `${razorpay.key_id.substring(0, 8)}...` : "NONE");
console.log("Final Razorpay Secret status:", razorpay.key_secret ? "TRIMMED & LOADED" : "NONE");

const resend = new Resend(process.env.RESEND_API_KEY);

// Rate limiter for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: "Too many login attempts, try again later" },
});

// ================== MONGOOSE MODELS ==================
const userSchema = new mongoose.Schema(
  { name: String, email: { type: String, unique: true }, password: String },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

const profileSchema = new mongoose.Schema({
  userId: String,
  name: String,
  email: String,
  phone: String,
  phoneCode: String,
  address: String,
  AlternatePhone: String,
  alternatePhoneCode: String,
  city: String,
  Pincode: String,
  street_area_locality: String,
  House_flat_building: String,
  landmark: String,
  district: String,
  state: String,
  country: String,
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

  userDetails: {
    name: String,
    phone: String,
    phoneCode: String,
    alternatePhone: String,
    alternatePhoneCode: String,
    address: {
      house: String,
      street: String,
      landmark: String,
      city: String,
      district: String,
      state: String,
      pincode: String,
      country: String,
    },
  },

  items: Array,
  total: Number,

  paymentId: String,
  razorpayOrderId: String,

  paymentStatus: {
    type: String,
    enum: ["Paid"],
    required: true,
  },

  deliveryStatus: {
    type: String,
    enum: [
      "Placed",
      "Confirmed",
      "Shipped",
      "Out for Delivery",
      "Delivered",
      "Cancelled"
    ],
    default: "Placed",
  },

  date: { type: Date, default: Date.now },
});



const Order = mongoose.model("Order", orderSchema);

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true },
    material: { type: String, required: true },

    price: { type: Number, required: true },
    stockAvailable: { type: Number, required: true },
    oldPrice: { type: Number, required: true },
    imageUrl: { type: [String], required: true },
    
    // Identity & Highlights
    productCode: { type: String, default: "" },
    region: { type: String, default: "" },
    tagline: { type: String, default: "Real Curry. No Chopping." },
    dietaryTags: { type: [String], default: [] },
    
    // Content & Story
    originStory: { type: String, default: "" },
    ingredients: { type: String, default: "" }, // Keep legacy for compatibility
    pouchContents: [{
      name: String,
      weight: String,
      note: String
    }],
    
    // Stats
    stats: {
      serves: { type: String, default: "" },
      prep: { type: String, default: "" },
      cook: { type: String, default: "" },
      protein: { type: String, default: "" },
    },
    
    // Cooking
    howToCook: { type: String, default: "" }, // Keep legacy for compatibility
    cookingSteps: { type: [String], default: [] },
    customerAdds: { type: String, default: "" },

    // Standard fields
    weight: { type: String, default: "" },
    serves: { type: String, default: "" }, // Keep legacy
    featured: Boolean,
    trending: Boolean,
  },
  { timestamps: true }
);
const Product = mongoose.model("Product", productSchema);



// ================== DATABASE CONNECTION ==================
let cachedConnection = null;
async function connectDB() {
  if (cachedConnection) return cachedConnection;
  if (!MONGO_URI) {
    console.error("MONGO_URI not set");
    process.exit(1);
  }
  cachedConnection = await mongoose.connect(MONGO_URI);
  console.log("MongoDB connected");
  return cachedConnection;
}
connectDB().catch(err => console.error("DB Error:", err));

// ================== AUTH MIDDLEWARE ==================
function authMiddleware(req, res, next) {
  const bearer = req.headers.authorization;
  if (!bearer) return res.status(401).json({ message: "No token" });
  const token = bearer.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// ================== ADMIN MIDDLEWARE ==================
const ADMIN_USER = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASS = process.env.ADMIN_PASSWORD || "admin123";

function adminMiddleware(req, res, next) {
  const adminToken = req.headers["admin-token"];
  if (!adminToken || adminToken !== process.env.JWT_SECRET + "_admin") {
    return res.status(403).json({ message: "Admin access denied" });
  }
  next();
}

app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    return res.json({ adminToken: process.env.JWT_SECRET + "_admin", success: true });
  }
  res.status(401).json({ message: "Invalid admin credentials", success: false });
});

app.get("/admin/users", adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select("-password").sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Error fetching users" });
  }
});

app.delete("/admin/users/:id", adminMiddleware, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Profile.deleteOne({ userId: req.params.id });
    res.json({ message: "User deleted" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting user" });
  }
});


// ================== RAZORPAY: CREATE ORDER ==================
app.post("/create-order", authMiddleware, async (req, res) => {
  try {
    const { amount, cart } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: "Invalid amount" });

    const order = await razorpay.orders.create({
      amount: Math.round(amount * 100), // paise
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
      notes: {
        userId: req.user.id.toString(),
        // Store truncated cart for webhook fallback (max 255 chars in Razorpay notes)
        cart: JSON.stringify(cart).substring(0, 255),
      },
    });

    res.json({
      id: order.id,
      amount: order.amount,
      currency: order.currency,
    });
  } catch (error) {
    console.error("Create order error:", error);
    res.status(500).json({ message: "Failed to create order" });
  }
});

// ================== RAZORPAY WEBHOOK ==================
// ================== RAZORPAY WEBHOOK (IMPROVED) ==================
app.post("/webhook/razorpay", async (req, res) => {
  // Use RAZORPAY_WEBHOOK_SECRET or fallback to RAZORPAY_KEY_SECRET for signature verification
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET || process.env.RAZORPAY_KEY_SECRET;
  const signature = req.headers["x-razorpay-signature"];

  const shasum = crypto.createHmac("sha256", secret);
  shasum.update(req.body);
  const digest = shasum.digest("hex");

  // Verify signature
  if (digest !== signature) {
    console.warn("Invalid Razorpay webhook signature");
    return res.status(400).send("Invalid signature");
  }

  let event;
  try {
    event = JSON.parse(req.body.toString());
  } catch (err) {
    return res.status(400).send("Invalid payload");
  }

  if (event.event === "payment.captured") {
    const payment = event.payload.payment.entity;
    const userId = payment.notes?.userId;
    const cartItemsJson = payment.notes?.cart;

    if (!userId || !cartItemsJson) {
      console.error("Missing userId or cart in payment notes");
      return res.status(200).send("OK"); // Still acknowledge
    }

    let cartItems;
    try {
      cartItems = JSON.parse(cartItemsJson);
    } catch (err) {
      console.error("Failed to parse cart items");
      return res.status(200).send("OK");
    }

    // Fetch product details to preserve name & price at time of purchase
    const enrichedItems = await Promise.all(
      cartItems.map(async (item) => {
        const product = await Product.findById(item.productId);
        return {
          productId: item.productId,
          name: product?.name || "Unknown Product",
          price: product?.price || 0,
          size: item.size,
          quantity: item.quantity,
          imageUrl: product?.imageUrl?.[0] || "",
        };
      })
    );

    const subtotal = enrichedItems.reduce(
      (sum, item) => sum + item.price * item.quantity,
      0
    );
    const shipping = subtotal >= 599 ? 0 : 49;
    const totalAmount = subtotal + shipping;

    const profile = await Profile.findOne({ userId });

    // Check for existing order with same razorpayOrderId to avoid duplicates
    const existingOrder = await Order.findOne({ razorpayOrderId: payment.order_id });
    if (existingOrder) {
      if (existingOrder.paymentStatus !== "Paid") {
        existingOrder.paymentStatus = "Paid";
        existingOrder.paymentId = payment.id;
        await existingOrder.save();
      }
      return res.status(200).send("OK");
    }

    await Order.create({
      userId,
      userDetails: {
        name: profile?.name || "",
        phone: profile?.phone || "",
        phoneCode: profile?.phoneCode || "+91",
        alternatePhone: profile?.AlternatePhone || "",
        alternatePhoneCode: profile?.alternatePhoneCode || "+91",
        address: {
          house: profile?.House_flat_building || "",
          street: profile?.street_area_locality || "",
          landmark: profile?.landmark || "",
          city: profile?.city || "",
          district: profile?.district || "",
          state: profile?.state || "",
          pincode: profile?.Pincode || "",
          country: profile?.country || "India",
        },
      },
      items: enrichedItems,
      total: totalAmount,
      paymentId: payment.id,
      razorpayOrderId: payment.order_id,
      paymentStatus: "Paid",
      deliveryStatus: "Placed",
      date: new Date(),
    });


    // Clear user's cart after successful payment
    await Cart.deleteMany({ userId });
  }

  res.status(200).send("OK");
});



// ================== AUTH ROUTES ==================
app.post("/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.status(400).json({ message: "Missing fields" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ success: false, statusCode: "400", message: "Email already exists", });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword });
    const profile = await Profile.create({ userId: user._id, name, email });

    const token = jwt.sign({ id: user._id, email }, JWT_SECRET, { expiresIn: "7d" });
    
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        name, 
        email,
        phone: profile.phone || "",
        phoneCode: profile.phoneCode || "+91",
        AlternatePhone: profile.AlternatePhone || "",
        alternatePhoneCode: profile.alternatePhoneCode || "+91",
        address: profile.address || "",
        House_flat_building: profile.House_flat_building || "",
        city: profile.city || "",
        Pincode: profile.Pincode || "",
        street_area_locality: profile.street_area_locality || "",
        landmark: profile.landmark || "",
        district: profile.district || "",
        state: profile.state || "",
        country: profile.country || "India",
      } 
    });
  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    res.status(500).json({ message: "Signup failed", success: false, statusCode: "500" });
  }
});


app.patch("/admin/orders/:id/delivery-status", adminMiddleware, async (req, res) => {
  const { deliveryStatus } = req.body;

  const allowed = [
    "Placed",
    "Confirmed",
    "Shipped",
    "Out for Delivery",
    "Delivered",
    "Cancelled",
  ];

  if (!allowed.includes(deliveryStatus)) {
    return res.status(400).json({ message: "Invalid delivery status" });
  }

  const order = await Order.findByIdAndUpdate(
    req.params.id,
    { deliveryStatus },
    { new: true }
  );

  if (!order) {
    return res.status(404).json({ message: "Order not found" });
  }

  res.json(order);
});


app.post("/loginWithEmail", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ success: false, status: 400, isVerified: false, message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email }, JWT_SECRET);
    const profile = await Profile.findOne({ userId: user._id });

    res.json({ 
      token, 
      isVerified: true, 
      success: true, 
      statusCode: 200, 
      Role: "Customer", 
      message: "Login succesfull", 
      timeStamp: new Date(), 
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email,
        address: profile?.address || "",
        phone: profile?.phone || "",
        phoneCode: profile?.phoneCode || "+91",
        AlternatePhone: profile?.AlternatePhone || "",
        alternatePhoneCode: profile?.alternatePhoneCode || "+91",
        House_flat_building: profile?.House_flat_building || "",
        city: profile?.city || "",
        Pincode: profile?.Pincode || "",
        street_area_locality: profile?.street_area_locality || "",
        landmark: profile?.landmark || "",
        district: profile?.district || "",
        state: profile?.state || "",
        country: profile?.country || "India",
      } 
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/forgot-password", async (req, res) => {
  // Your existing forgot-password code (unchanged)
  // ... (keep exactly what you already have)
});

app.post("/reset-password/:token", async (req, res) => {
  // Your existing reset-password code (unchanged)
  // ... (keep exactly what you already have)
});

app.get("/auth/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("name email");
    if (!user) {
      return res.status(401).json({ isUser: false });
    }

    const profile = await Profile.findOne({ userId: req.user.id });

    res.json({
      status: {

        isUser: true,
        isVerified: true,
        StatusCode: 200,


      },
      isUser: true,   // 👈 THIS is what you asked for
      id: user._id,
      name: user.name,
      email: user.email,
      address: profile?.address || "",
      phone: profile?.phone || "",
      phoneCode: profile?.phoneCode || "+91",
      AlternatePhone: profile?.AlternatePhone || "",
      alternatePhoneCode: profile?.alternatePhoneCode || "+91",
      House_flat_building: profile?.House_flat_building || "",
      city: profile?.city || "",
      Pincode: profile?.Pincode || "",
      street_area_locality: profile?.street_area_locality || "",
      landmark: profile?.landmark || "",
      district: profile?.district || "",
      state: profile?.state || "",
      country: profile?.country || "India",
    });
  } catch (err) {
    res.status(401).json({ isUser: false });
  }
});


// ================== PRODUCTS ==================
app.post("/products", adminMiddleware, async (req, res) => {
  try {
    const saved = await Product.create(req.body);
    res.json(saved);
  } catch (e) {
    console.error("PRODUCT SAVE ERROR:", e);
    res.status(500).json({ message: "Product save failed" });
  }
});

app.get("/products", async (req, res) => {
  try {
    const {
      category,
      minPrice,
      maxPrice,
      sort,
      page = 1,
      limit = 100,
    } = req.query;

    const filter = {};

    if (category) filter.category = category;
    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = Number(minPrice);
      if (maxPrice) filter.price.$lte = Number(maxPrice);
    }

    let query = Product.find(filter);

    if (sort === "asc") query = query.sort({ price: 1 });
    if (sort === "desc") query = query.sort({ price: -1 });

    const skip = (Number(page) - 1) * Number(limit);

    const [products, total] = await Promise.all([
      query.skip(skip).limit(Number(limit)).exec(),
      Product.countDocuments(filter),
    ]);

    res.json({
      products,
      total,
      page: Number(page),
      totalPages: Math.ceil(total / Number(limit)),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch products" });
  }
});


app.put("/products/:id", adminMiddleware, async (req, res) => {
  try {
    const updated = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    if (!updated) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json({ message: "Product updated", product: updated });
  } catch (err) {
    res.status(500).json({ message: "Error updating product", error: err });
  }
});


app.delete("/products/:id", adminMiddleware, async (req, res) => {
  try {
    const removed = await Product.findByIdAndDelete(req.params.id);

    if (!removed) {
      return res.status(404).json({ message: "Product not found" });
    }

    res.json({ message: "Product deleted" });
  } catch (err) {
    res.status(500).json({ message: "Error deleting product", error: err });
  }
});


app.get("/products/featured", async (req, res) => res.json(await Product.find({ featured: true })));
app.get("/products/trending", async (req, res) => res.json(await Product.find({ trending: true })));
app.get("/products/:id", async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Not found" });
    res.json(product);
  } catch {
    res.status(500).json({ message: "Failed" });
  }
});

// ================== CART ==================
app.get("/cart", authMiddleware, async (req, res) => res.json(await Cart.find({ userId: req.user.id })));
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

// ================== WISHLIST ==================
app.get("/wishlist", authMiddleware, async (req, res) => res.json(await Wishlist.find({ userId: req.user.id })));
app.post("/wishlist/:productId", authMiddleware, async (req, res) => {
  await Wishlist.create({ userId: req.user.id, productId: req.params.productId });
  res.json({ message: "Added" });
});
app.delete("/wishlist/:productId", authMiddleware, async (req, res) => {
  await Wishlist.deleteOne({ userId: req.user.id, productId: req.params.productId });
  res.json({ message: "Removed" });
});

// ================== ORDERS ==================
app.get("/orders", authMiddleware, async (req, res) => {
  const orders = await Order.find({ userId: req.user.id }).sort({ date: -1 });
  res.json(orders);
});

// ================== USER CANCEL ORDER ==================
app.patch("/orders/:id/cancel", authMiddleware, async (req, res) => {
  try {
    const order = await Order.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });

    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }

    if (order.deliveryStatus !== "Placed") {
      return res.status(400).json({
        message: "Order cannot be cancelled after confirmation",
      });
    }

    order.deliveryStatus = "Cancelled";
    await order.save();

    res.json({ message: "Order cancelled successfully", order });
  } catch (error) {
    console.error("Cancel order error:", error);
    res.status(500).json({ message: "Failed to cancel order" });
  }
});


app.post("/orders", authMiddleware, async (req, res) => {
  try {
    const { items, totalAmount, paymentId, razorpayOrderId, status, shippingAddress } = req.body;
    const userId = req.user.id;

    // Enrich items with product name & current price
    const enrichedItems = await Promise.all(
      items.map(async (item) => {
        const product = await Product.findById(item.productId);
        return {
          productId: item.productId,
          name: product?.name || "Unknown Product",
          price: product?.price || 0,
          size: item.size || "",
          quantity: item.quantity || 1,
          imageUrl: product?.imageUrl?.[0] || "",
        };
      })
    );

    const total = totalAmount || enrichedItems.reduce(
      (sum, item) => sum + item.price * item.quantity,
      0
    );

    const profile = await Profile.findOne({ userId });

    // Check if order already exists (possibly created by webhook)
    if (razorpayOrderId) {
      const existing = await Order.findOne({ razorpayOrderId });
      if (existing) {
        if (status === "Paid" && existing.paymentStatus !== "Paid") {
          existing.paymentStatus = "Paid";
          existing.paymentId = paymentId;
          await existing.save();
        }
        return res.json(existing);
      }
    }

    const order = await Order.create({
      userId,
      userDetails: {
        name: profile?.name || req.user.name || "",
        phone: shippingAddress?.phone || profile?.phone || "",
        phoneCode: shippingAddress?.phoneCode || profile?.phoneCode || "+91",
        alternatePhone: shippingAddress?.alternatePhone || profile?.AlternatePhone || "",
        alternatePhoneCode: shippingAddress?.alternatePhoneCode || profile?.alternatePhoneCode || "+91",
        address: {
          house: shippingAddress?.house || profile?.House_flat_building || "",
          street: shippingAddress?.street || profile?.street_area_locality || "",
          landmark: shippingAddress?.landmark || profile?.landmark || "",
          city: shippingAddress?.city || profile?.city || "",
          district: shippingAddress?.district || profile?.district || "",
          state: shippingAddress?.state || profile?.state || "",
          pincode: shippingAddress?.pincode || profile?.Pincode || "",
          country: shippingAddress?.country || profile?.country || "India",
        },
      },
      items: enrichedItems,
      total,
      paymentId: paymentId || null,
      razorpayOrderId: razorpayOrderId || null,
      paymentStatus: "Paid",
      deliveryStatus: "Placed",
      date: new Date(),
    });

    // Clear cart after order
    await Cart.deleteMany({ userId });

    res.json(order);
  } catch (error) {
    console.error("Order creation failed:", error);
    res.status(500).json({ message: "Failed to create order" });
  }
});



app.get("/admin/orders", adminMiddleware, async (req, res) => {
  const orders = await Order.find().sort({ date: -1 });
  res.json(orders);
});


// ================== PROFILE ==================
app.get("/profile", authMiddleware, async (req, res) => {
  res.json(await Profile.findOne({ userId: req.user.id }));
});
app.put("/profile", authMiddleware, async (req, res) => {
  try {
    const { userId, ...updateData } = req.body; // Remove userId from body to prevent overwrite
    
    console.log("Saving Profile for user:", req.user.id, updateData);

    // Update User model name if provided
    if (updateData.name) {
      await User.findByIdAndUpdate(req.user.id, { name: updateData.name });
    }

    const updated = await Profile.findOneAndUpdate(
      { userId: req.user.id },
      { ...updateData },
      { new: true, upsert: true }
    );

    // Fetch fresh user data to return
    const user = await User.findById(req.user.id).select("name email");
    
    res.json({
      ...updated.toObject(), // Spread all profile fields
      id: user._id,          // Ensure id, name, and email are correct
      name: user.name,
      email: user.email,
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ message: "Failed to update profile" });
  }
});

// ================== HEALTH & ROOT ==================
app.get("/health", (req, res) => {
  res.json({ status: "ok", mongo: mongoose.connection.readyState === 1 ? "connected" : "down" });
});

app.get("/", (req, res) => {
  res.send(`Pocket chef Backend is running..`);
});

// ================== START SERVER ==================
if (!runningOnVercel) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Webhook URL: https://foodiesdelight.vercel.app/webhook/razorpay`);
  });
}

export default app;










