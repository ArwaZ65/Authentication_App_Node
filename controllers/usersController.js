const User = require("../models/User");
const getAllUsers = async (req, res) => {
  const users = await User.find().select("-password").lean(); //retive all data without pass
  if (!users.length) { //if user not found
    return res.status(400).json({ message: "No users found" });
  }
  res.json(users);
};
module.exports = {
  getAllUsers,
};
