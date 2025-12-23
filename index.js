import express, { response } from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import { Resend } from "resend";
import Razorpay from "razorpay";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(express.json());
app.set("json spaces", 2);

app.use(cors());

// IMPORTANT: Raw body for Razorpay webhook only
app.use("/webhook/razorpay", express.raw({ type: "application/json" }));

const JWT_SECRET = process.env.JWT_SECRET || "local_dev_secret_2025";
const MONGO_URI = process.env.MONGO_URI;
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL ;
const runningOnVercel = process.env.VERCEL === "1";

// Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

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
  address: String,
  AlternatePhone: String,
  city: String,
  Pincode: String,
  street_area_locality: String,
  House_flat_building: String,
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
    address: {
      house: String,
      street: String,
      city: String,
      pincode: String,
    },
  },

  items: Array,
  total: Number,

  paymentId: String,
  razorpayOrderId: String,

  paymentStatus: {
    type: String,
    enum: ["Paid", "COD"],
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

// ================== RAZORPAY: CREATE ORDER ==================
app.post("/create-order", authMiddleware, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: "Invalid amount" });

    const order = await razorpay.orders.create({
      amount: Math.round(amount * 100), // paise
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
      notes: {
        userId: req.user.id.toString(),
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
  const secret = process.env.RAZORPAY_KEY_SECRET;
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

    const totalAmount = enrichedItems.reduce(
      (sum, item) => sum + item.price * item.quantity,
      0
    );

    const profile = await Profile.findOne({ userId });

    await Order.create({
  userId,
  userDetails: {
    name: profile?.name || "",
    phone: profile?.phone || "",
    address: {
      house: profile?.House_flat_building || "",
      street: profile?.street_area_locality || "",
      city: profile?.city || "",
      pincode: profile?.Pincode || "",
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
    if (existing) return res.status(400).json({success:false , statusCode:"400",   message: "Email already exists",});

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword });
    await Profile.create({ userId: user._id, name, email });

    const token = jwt.sign({ id: user._id, email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: { id: user._id, name, email } });
  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    res.status(500).json({ message: "Signup failed",success:false,statusCode:"500" });
  }
});


app.patch("/admin/orders/:id/delivery-status", authMiddleware, async (req, res) => {
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
    if (!match) return res.status(400).json({success:false,status:400,isVerified:false, message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email }, JWT_SECRET);
    res.json({ token, isVerified:true,success:true,statusCode:200,Role:"Customer",message:"Login succesfull",timeStamp:new Date(),user: { id: user._id, name: user.name, email: user.email } });
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
    status:{

      isUser: true,
      isVerified: true,
      StatusCode: 200,
      

    },
      isUser: true,   // 👈 THIS is what you asked for
      id: user._id,
      name: user.name,
      email: user.email,
      phone: profile?.phone || "",
      AlternatePhone: profile?.AlternatePhone || "",
      House_flat_building: profile?.House_flat_building || "",
      city: profile?.city || "",
      Pincode: profile?.Pincode || "",
      street_area_locality: profile?.street_area_locality || "",
    });
  } catch (err) {
    res.status(401).json({ isUser: false });
  }
});


// ================== PRODUCTS ==================
app.post("/products", async (req, res) => {
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
      limit = 8,
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


app.put("/products/:id", async (req, res) => {
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


app.delete("/products/:id", async (req, res) => {
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
    const { items } = req.body;

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

    const total = enrichedItems.reduce(
      (sum, item) => sum + item.price * item.quantity,
      0
    );

    const profile = await Profile.findOne({ userId });

   const order = await Order.create({
  userId,
  userDetails: {
    name: profile?.name || "",
    phone: profile?.phone || "",
    address: {
      house: profile?.House_flat_building || "",
      street: profile?.street_area_locality || "",
      city: profile?.city || "",
      pincode: profile?.Pincode || "",
    },
  },
  items: enrichedItems,
  total,
  paymentStatus: "COD",
  deliveryStatus: "Placed",
  date: new Date(),
});


    // Optional: clear cart
    await Cart.deleteMany({ userId });

    res.json(order);
  } catch (error) {
    console.error("Manual order creation failed:", error);
    res.status(500).json({ message: "Failed to create order" });
  }
});



app.get("/admin/orders", authMiddleware, async (req, res) => {
  const orders = await Order.find().sort({ date: -1 });
  res.json(orders);
});


// ================== PROFILE ==================
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

// ================== HEALTH & ROOT ==================
app.get("/health", (req, res) => {
  res.json({ status: "ok", mongo: mongoose.connection.readyState === 1 ? "connected" : "down" });
});

app.get("/", (req, res) => {
  res.send(`Drip Jersey Backend is running..`);
});

// ================== START SERVER ==================
if (!runningOnVercel) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Webhook URL: https://dripjerseyco.vercel.app/webhook/razorpay`);
  });
}

export default app;










