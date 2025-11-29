import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import rateLimit from "express-rate-limit"; // ✅ Rate limiter added
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || "local_dev_secret";
const MONGO_URI =
  process.env.MONGO_URI ;
const PORT = process.env.PORT ;
const runningOnVercel = process.env.VERCEL === "1";

// ------------------ RATE LIMITER ------------------ //

// 5 login attempts per 15 minutes per IP
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    message: "Too many login attempts. Try again in 15 minutes.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ------------------ SCHEMAS ------------------ //

// USER
const userSchema = new mongoose.Schema(
  {
    name: String,
    email: { type: String, unique: true },
    password: String,
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

// PROFILE
const profileSchema = new mongoose.Schema({
  userId: String,
  name: String,
  email: String,
  phone: String,
  address: String,
});
const Profile = mongoose.model("Profile", profileSchema);

// CART
const cartSchema = new mongoose.Schema({
  userId: String,
  productId: String,
  quantity: Number,
  size: String,
});
const Cart = mongoose.model("Cart", cartSchema);

// WISHLIST
const wishlistSchema = new mongoose.Schema({
  productName: String,
  userId: String,
  productId: String,
  date: Date,
});
const Wishlist = mongoose.model("Wishlist", wishlistSchema);

// ORDERS
const orderSchema = new mongoose.Schema({
  userId: String,
  name: String,
  category: String,
  items: Array,
  total: Number,
  date: Date,
});
const Order = mongoose.model("Order", orderSchema);

// PRODUCT
const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    description: { type: String, required: true },
    category: { type: String, required: true },
    price: { type: Number, required: true },
    imageUrl: { type: [String], required: true },
    featured: Boolean,
    trending: Boolean,
  },
  { timestamps: true }
);

const Product = mongoose.model("Product", productSchema);

// ------------------ CONNECT MDB ------------------ //

let cachedConnection = null;
let cachedPromise = null;

async function connectDB() {
  if (cachedConnection) return cachedConnection;

  if (!cachedPromise) {
    cachedPromise = mongoose.connect(MONGO_URI).then((mongooseInstance) => {
      console.log("MongoDB connected");
      cachedConnection = mongooseInstance.connection;
      return cachedConnection;
    });
  }

  try {
    return await cachedPromise;
  } catch (err) {
    console.error("MongoDB error:", err);
    cachedPromise = null;
    cachedConnection = null;
    if (!runningOnVercel) {
      process.exit(1);
    }
    throw err;
  }
}
connectDB();

// ------------------ AUTH MIDDLEWARE ------------------ //

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

// ------------------ AUTH ROUTES ------------------ //

// SIGNUP — WITH HASHED PASSWORD
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

    await Profile.create({
      userId: user._id,
      name,
      email,
    });

    const token = jwt.sign({ id: user._id, email }, JWT_SECRET);

    return res.json({ token, user });
  } catch (err) {
    console.error("SIGNUP ERROR:", err);

    if (err.code === 11000) {
      return res.status(400).json({ message: "Email already exists" });
    }

    return res.status(500).json({ message: "Signup failed" });
  }
});

// LOGIN — NOW RATE LIMITED
app.post("/loginWithEmail", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, email }, JWT_SECRET);

    res.json({ token, user });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ message: "Login failed" });
  }
});

// ------------------ USER ------------------ //

app.get("/auth/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("name email");
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

// ------------------ PRODUCTS ------------------ //

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
    if (sort === "asc") query.sort({ price: 1 });
    if (sort === "desc") query.sort({ price: -1 });

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

// ------------------ CART ------------------ //

app.get("/cart", authMiddleware, async (req, res) => {
  res.json(await Cart.find({ userId: req.user.id }));
});

app.post("/cart", authMiddleware, async (req, res) => {
  const saved = await Cart.create({
    userId: req.user.id,
    ...req.body,
  });
  res.json(saved);
});

app.put("/cart/:id", authMiddleware, async (req, res) => {
  const updated = await Cart.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.json(updated);
});

app.delete("/cart/:id", authMiddleware, async (req, res) => {
  await Cart.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

// ------------------ WISHLIST ------------------ //

app.get("/wishlist", authMiddleware, async (req, res) => {
  res.json(await Wishlist.find({ userId: req.user.id }));
});

app.post("/wishlist/:productId", authMiddleware, async (req, res) => {
  try {
    await Wishlist.create({
      userId: req.user.id,
      productId: req.params.productId,
    });
    res.json({ message: "Added" });
  } catch (err) {
    res.status(500).json({ message: "Failed to add" });
  }
});

app.delete("/wishlist/:productId", authMiddleware, async (req, res) => {
  await Wishlist.deleteOne({
    userId: req.user.id,
    productId: req.params.productId,
  });
  res.json({ message: "Removed" });
});

// ------------------ ORDERS (USER) ------------------ //

app.get("/orders", authMiddleware, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.id });
    const profile = await Profile.findOne({ userId: req.user.id }).select(
      "name email phone address"
    );

    const detailedOrders = await Promise.all(
      orders.map(async (order) => {
        const detailedItems = await Promise.all(
          order.items.map(async (item) => {
            const product = await Product.findById(item.productId);
            return {
              ...item,
              productName: product?.name || "",
              productPrice: product?.price || 0,
              imageUrl: product?.imageUrl || "",
              category: product?.category || "",
            };
          })
        );

        return {
          orderId: order._id,
          email: profile.email,
          phone: profile.phone,
          address: profile.address,
          total: order.total,
          date: order.date,
          items: detailedItems,
        };
      })
    );

    res.json(detailedOrders);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch orders" });
  }
});

app.post("/orders", authMiddleware, async (req, res) => {
  try {
    const order = await Order.create({
      userId: req.user.id,
      ...req.body,
      date: new Date(),
    });
    res.json(order);
  } catch (err) {
    res.status(500).json({ message: "Order failed" });
  }
});

// ------------------ ADMIN ORDERS ------------------ //

app.get("/admin/orders", async (req, res) => {
  try {
    const orders = await Order.find({});

    const detailedOrders = await Promise.all(
      orders.map(async (order) => {
        const user = await User.findById(order.userId).select("name email");
        const profile = await Profile.findOne({ userId: order.userId }).select(
          "name email phone address"
        );

        const detailedItems = await Promise.all(
          order.items.map(async (item) => {
            const product = item.productId
              ? await Product.findById(item.productId).select(
                  "name price category imageUrl"
                )
              : null;

            return {
              ...item,
              productName: product?.name || "Unknown Product",
              productPrice: product?.price || 0,
              category: product?.category || "Unknown",
              imageUrl: product?.imageUrl || "",
            };
          })
        );

        return {
          orderId: order._id,
          name: profile?.name || user?.name || "Unknown",
          email: profile?.email || user?.email || "Unknown",
          phone: profile?.phone || "Not Provided",
          address: profile?.address || "Not Provided",
          total: order.total,
          date: order.date,
          items: detailedItems,
        };
      })
    );

    res.json(detailedOrders);
  } catch (err) {
    console.error("ADMIN ORDER ERROR:", err);
    res.status(500).json({ message: "Failed to fetch admin orders" });
  }
});

// ------------------ PROFILE ------------------ //

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

// ------------------ HEALTH ------------------ //

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    mongo: mongoose.connection.readyState === 1 ? "connected" : "down",
  });
});

// ------------------ HOME PAGE ------------------ //

app.get("/", (req, res) => {
  res.send(`
      <div style="font-family: Arial; padding: 40px; ;">
        <p> Server is Running Successfully..</p>
      </div>
    `);
});

// ------------------ SERVER ------------------ //

if (!runningOnVercel) {
  app.listen(PORT, () =>
    console.log(`Server running on http://localhost:${PORT}`)
  );
}

export default app;
