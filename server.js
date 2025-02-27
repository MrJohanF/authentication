// src/app/server.js

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import authRoutes from "./routes/auth.js";
import authMiddleware from "./middleware/auth.js";

const app = express();

// Middleware
app.use(
  cors({
    origin: [
      "https://ucommerce.live",
      "https://www.ucommerce.live",
      "http://localhost:3000",
      "https:api.ucommerce.live",
      'https:www.api.ucommerce.live',
      'https://e-commerce-mrjohanfs-projects.vercel.app',
    ],
    credentials: true,
  })
);


app.use(express.json());
app.use(cookieParser());

// Routes
app.use("/api/auth", authRoutes);

app.get("/api/protected", authMiddleware, (req, res) => {
  res.json({
    message: "This is a protected route",
    user: req.user,
  });
});

app.use((err, req, res, next) => {
  res.status(500).json({
    message: "Something went wrong",
    error: err.message,
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
