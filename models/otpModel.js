const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, expires: `${process.env.OTP_EXPIRY}m`, default: Date.now },
});

module.exports = mongoose.model("OTP", otpSchema);
