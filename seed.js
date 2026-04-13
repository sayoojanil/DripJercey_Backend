import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config();

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
    featured: Boolean,
    trending: Boolean,
  },
  { timestamps: true }
);

const Product = mongoose.models.Product || mongoose.model("Product", productSchema);

const seedProducts = [];

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/foodiesdelight";

async function runSeed() {
  try {
    console.log("Connecting to MongoDB...");
    await mongoose.connect(MONGO_URI);
    
    console.log("Connected. Clearing old products...");
    await Product.deleteMany({});
    
    console.log("Inserting new food products...");
    await Product.insertMany(seedProducts);
    
    console.log("Database seeded successfully!");
    mongoose.connection.close();
  } catch (err) {
    console.error("Error seeding database:", err);
    process.exit(1);
  }
}

runSeed();
