require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const crypto = require("crypto");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken'); // Add this for JWT

const OTPModel = require("./models/otpModel");

// Create User Model
const UserSchema = new mongoose.Schema({
  uuid: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  ageRange: { type: String, required: true },
  gender: { type: String, required: true },
  emailVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);

// Create verification status model
const VerificationSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  verified: { type: Boolean, default: false },
  verifiedAt: { type: Date },
  expiresAt: { type: Date, default: () => new Date(Date.now() + 30 * 60000) } // 30 minutes expiry
});

const Verification = mongoose.model("Verification", VerificationSchema);

const app = express();
app.use(express.json());
app.use(cors()); 

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Error connecting to MongoDB:", err));

const allowedDomains = ["@gmail.com", "@yahoo.com", "@outlook.com"]; 

// Create middleware to check email domain
const checkEmailDomain = (req, res, next) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  // Check if the email ends with one of the allowed domains
  const isValidDomain = allowedDomains.some(domain => email.endsWith(domain));
  
  if (!isValidDomain) {
    return res.status(400).json({ message: `Enter Valid Email ID` });
  }

  next();  
};

// Auth middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN format
  
  if (!token) return res.status(401).json({ message: "Authentication required" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token" });
    req.user = user;
    next();
  });
};

// Generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    { uuid: user.uuid, email: user.email }, 
    process.env.JWT_SECRET, 
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

const transporter = nodemailer.createTransport({
  host: "smtp.hostinger.com", 
  port: 587, 
  secure: false, 
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, 
  },
});

const generateOTP = () => crypto.randomInt(1000, 9999).toString();

const sendOTP = async (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER, 
    to: email,                    
    subject: "🔐 Your One-Time Password for Verification",  
    html: `<!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>OTP Verification</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              background-color: #f4f4f9;
              margin: 0;
              padding: 20px;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              background-color: #fff;
              border-radius: 8px;
              padding: 30px;
              box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
            }
            h2 {
              color: #333;
              font-size: 32px;
              margin-bottom: 20px;
              text-align: center;
            }
            p {
              color: #555;
              font-size: 16px;
              line-height: 1.5;
              margin-bottom: 20px;
            }
            .otp {
              display: block;
              background-color: #4CAF50;
              color: white;
              font-size: 24px;
              font-weight: bold;
              padding: 10px 20px;
              border-radius: 6px;
              text-align: center;
              margin: 20px 0;
            }
            .footer {
              text-align: center;
              font-size: 12px;
              color: #777;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h2>Your One-Time Password (OTP) for Verification</h2>
            <p>We received a request to verify your identity. Please use the one-time password (OTP) below to complete the verification process:</p>
            <span class="otp">${otp}</span>
            <p>Note: This OTP is valid for ${process.env.OTP_EXPIRY} minutes from the time of request.</p>
            <p>If you did not request this verification, please ignore this email.</p>
            <div class="footer">
              <p>&copy; ${new Date().getFullYear()} ShoreTic. All rights reserved.</p>
            </div>
          </div>
        </body>
      </html>`
  };

  await transporter.sendMail(mailOptions);  // Sends the email
};

// Login with email only (starts OTP process)
app.post("/request-otp", checkEmailDomain, async (req, res) => {
  const { email } = req.body;
  const otp = generateOTP();

  // Upsert OTP in MongoDB
  await OTPModel.findOneAndUpdate(
    { email },
    { otp, createdAt: new Date() },
    { upsert: true, new: true }
  );

  await sendOTP(email, otp);
  res.json({ message: "OTP sent successfully" });
});

// Verify OTP and issue JWT if successful
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ message: "Email and OTP are required" });

  const storedOTP = await OTPModel.findOne({ email });

  if (!storedOTP) return res.status(400).json({ message: "OTP expired or invalid" });
  if (storedOTP.otp !== otp) return res.status(400).json({ message: "Incorrect OTP" });

  // OTP verified, delete it
  await OTPModel.deleteOne({ email });

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  
  if (existingUser) {
    // Generate JWT token for existing user
    const token = generateToken(existingUser);
    
    // Return user data and token
    return res.json({ 
      message: "OTP verified successfully",
      userExists: true,
      user: {
        uuid: existingUser.uuid,
        email: existingUser.email,
        name: existingUser.name,
        ageRange: existingUser.ageRange,
        gender: existingUser.gender
      },
      token: token
    });
  }

  // Create or update verification record for this email
  await Verification.findOneAndUpdate(
    { email },
    { 
      verified: true, 
      verifiedAt: new Date(),
      expiresAt: new Date(Date.now() + 30 * 60000) // 30 minutes expiry 
    },
    { upsert: true, new: true }
  );

  res.json({ 
    message: "OTP verified successfully",
    userExists: false
  });
});

// User Signup (now issues JWT after signup)
app.post("/signup", async (req, res) => {
  const { email, name, ageRange, gender } = req.body;
  
  // Validate required fields
  if (!email || !name || !ageRange || !gender) {
    return res.status(400).json({ message: "All fields are required" });
  }

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    // Generate token for existing user
    const token = generateToken(existingUser);
    
    return res.json({ 
      message: "User already exists",
      userExists: true,
      user: {
        uuid: existingUser.uuid,
        email: existingUser.email,
        name: existingUser.name,
        ageRange: existingUser.ageRange,
        gender: existingUser.gender
      },
      token: token
    });
  }

  // Check if email is verified
  const verification = await Verification.findOne({ email });
  
  if (!verification || !verification.verified || verification.expiresAt < new Date()) {
    return res.status(403).json({ 
      message: "Email not verified or verification expired",
      userExists: false
    });
  }

  // Create new user
  const newUser = new User({
    uuid: uuidv4(),
    email,
    name,
    ageRange,
    gender,
    emailVerified: true
  });

  await newUser.save();
  
  // Generate token for new user
  const token = generateToken(newUser);

  res.status(201).json({ 
    message: "User created successfully",
    userExists: false,
    user: {
      uuid: newUser.uuid,
      email: newUser.email,
      name: newUser.name,
      ageRange: newUser.ageRange,
      gender: newUser.gender
    },
    token: token
  });
});

// Verify token endpoint (to check if token is valid)
app.get("/verify-token", authenticateToken, async (req, res) => {
  // If middleware passes, token is valid
  const user = await User.findOne({ uuid: req.user.uuid });
  
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  
  res.json({ 
    message: "Token is valid",
    user: {
      uuid: user.uuid,
      email: user.email,
      name: user.name,
      ageRange: user.ageRange,
      gender: user.gender
    }
  });
});

// Example of a protected route
app.get("/protected-route", authenticateToken, (req, res) => {
  res.json({ message: "This is a protected route", user: req.user });
});

// Start Server
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});