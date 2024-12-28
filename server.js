require("dotenv").config();
const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = 4000; // Middleware server runs on port 4000

const supabase = createClient(
  process.env.PUBLIC_SUPABASE_URL, // Supabase URL
  process.env.PUBLIC_SUPABASE_ANON_KEY // Supabase Anon Key
);

// Validate the target API base URL
const apiBaseUrl = process.env.API_BASE_URL;
if (!apiBaseUrl) {
  throw new Error("API_BASE_URL is not defined in the environment variables.");
}

// Middleware to verify JWT Token
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) {
      return res
        .status(401)
        .json({ message: "Access Denied. No token provided." });
    }

    // Verify JWT Signature
    const secret = process.env.JWT_SECRET;
    const decoded = jwt.verify(token, secret); // Decoded payload should match { id: userId }

    console.log(decoded);
    // Check if token exists in Supabase
    const { data, error } = await supabase
      .from("tokens")
      .select("*")
      .eq("user_id", decoded.id) // Match user ID
      .eq("token", token) // Match token
      .single();

    console.log(data, error);

    if (error || !data) {
      return res.status(403).json({ message: "Invalid or expired token." });
    }

    // Attach user ID to the request object for later use
    req.userId = decoded.id;
    next(); // Proceed if valid
  } catch (error) {
    console.error("Token verification error:", error.message);
    return res.status(403).json({ message: "Invalid Token" });
  }
}

// Proxy middleware to forward requests
const apiProxy = createProxyMiddleware({
  target: apiBaseUrl, // Redirect to actual API server
  changeOrigin: true,
  onProxyReq: (proxyReq, req, res) => {
    // Optionally modify the request before sending it to the API
  },
  onProxyRes: (proxyRes, req, res) => {
    // Optionally modify the response before sending it back to the client
  },
});

// Apply authentication middleware before proxying requests
app.use("/", authenticateToken, apiProxy);

// Start the middleware server
app.listen(PORT, () => {
  console.log(`Middleware server running on http://localhost:${PORT}`);
});
