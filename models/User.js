//schema
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    //id generates by default
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    // 🔐 Fields for password reset
    passwordResetToken: String,
    passwordResetCode: Number,
    passwordResetExpires: Date,

  },
  { timestamps: true }
);
module.exports = mongoose.model("User", userSchema);
