require("dotenv").config();
const express = require("express");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const crypto = require("crypto");
const cors = require("cors");
const rateLimit = require("express-rate-limit");


const OTPModel = require("./models/otpModel");

const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.connection.once("open", () => console.log("Connected to MongoDB"));

const otpRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, 
  message: "Too many requests from this IP, please try again later",
});

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
    subject: "🔐 Your One-Time Password for Verification",  // Improved Subject with Emoji
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


// API: Request OTP
app.post("/request-otp",otpRateLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

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

// API: Verify OTP
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ message: "Email and OTP are required" });

  const storedOTP = await OTPModel.findOne({ email });

  if (!storedOTP) return res.status(400).json({ message: "OTP  expired or invalid" });
  if (storedOTP.otp !== otp) return res.status(400).json({ message: "Incorrect OTP" });

  // OTP verified, delete it
  await OTPModel.deleteOne({ email });

  res.json({ message: "OTP verified successfully" });
});

// Start Server
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
