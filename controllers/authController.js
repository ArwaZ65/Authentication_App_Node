const User = require('../models/User');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sendEmail = require('../utils/email');
const jwt = require('jsonwebtoken');
//register
const register = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  const foundUser = await User.findOne({ email }).exec();
  if (foundUser) {
    return res.status(401).json({ message: 'User already exists' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await User.create({
    name,
    email,
    password: hashedPassword,
  });
  const accessToken = jwt.sign(
    {
      UserInfo: {
        id: user._id,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' }
  );
  const refreshToken = jwt.sign(
    {
      UserInfo: {
        id: user._id,
      },
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
  res.cookie('jwt', refreshToken, { //SAVe in browser
    httpOnly: true, //accessible only by web server
    secure: true, //https
    sameSite: 'None', //cross-site cookie
    maxAge: 7 * 24 * 60 * 60 * 1000, //expiried by minisecond
  });
   res.status(201).json({
    accessToken,
    email: user.email,
    name: user.name,
  });
};
//login
const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  const foundUser = await User.findOne({ email }).exec();
  if (!foundUser) {
    return res.status(401).json({ message: 'User does not exist' });
  }
  const match = await bcrypt.compare(password, foundUser.password);

  if (!match) return res.status(401).json({ message: 'Wrong Password please try again' });

  const accessToken = jwt.sign(
    {
      UserInfo: {
        id: foundUser._id,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' }
  );
  const refreshToken = jwt.sign(
    {
      UserInfo: {
        id: foundUser._id,
      },
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
  res.cookie('jwt', refreshToken, {
    httpOnly: true, //accessible only by web server
    secure: true, //https
    sameSite: 'None', //cross-site cookie
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.json({
    accessToken,
    email: foundUser.email,
  });
};
//update token dynamically
const refresh = (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) res.status(401).json({ message: 'Unauthorized' });
  const refreshToken = cookies.jwt;
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      if (err) return res.status(403).json({ message: 'Forbidden' });
      const foundUser = await User.findById(decoded.UserInfo.id).exec();
      if (!foundUser) return res.status(401).json({ message: 'Unauthorized' });
      const accessToken = jwt.sign(
        {
          UserInfo: {
            id: foundUser._id,
          },
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
      );
      res.json({ accessToken });
    }
  );
};
// Forgot Password
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetCode = Math.floor(100000 + Math.random() * 900000);

    user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.passwordResetCode = resetCode;
    user.passwordResetExpires = Date.now() + 15 * 60 * 1000;

    await user.save({ validateBeforeSave: false });

    await sendEmail({
      email: user.email,
      subject: 'Your password reset code (valid for 15 min)',
      message: `Your password reset code is ${resetCode}`
    });

    return res.status(200).json({ success: true, message: 'Reset code sent', token: resetToken });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

// Verify Code
const verifyResetCode = async (req, res) => {
  const { code, token } = req.body;

  if (!token) {
    return res.status(400).json({ success: false, message: 'Reset token is required' });
  }

  if (!code) {
    return res.status(400).json({ success: false, message: 'Reset code is required' });
  }

  try {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Token is invalid or expired' });
    }

    if (user.passwordResetCode !== parseInt(code)) {
      return res.status(400).json({ success: false, message: 'Invalid reset code' });
    }

    return res.status(200).json({ success: true, message: 'Code verified successfully' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

// Reset Password
const resetPassword = async (req, res) => {
  const token = req.params.token;
  const { password } = req.body;
  try {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Token is invalid or expired' });
    }

    user.password = await bcrypt.hash(password, 10);
    user.passwordResetToken = undefined;
    user.passwordResetCode = undefined;
    user.passwordResetExpires = undefined;

    await user.save();

    await sendEmail({
      email: user.email,
      subject: 'Password successfully changed',
      message: 'Your password has been updated successfully.'
    });

    return res.status(200).json({ success: true, message: 'Password updated successfully' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

//logout
const logout = (req, res) => {
  const cookies = req.cookies;//delete cookie
  if (!cookies?.jwt) return res.sendStatus(204); //No content
  res.clearCookie('jwt', {
    httpOnly: true,
    sameSite: 'None',
    secure: true,
  });
  res.json({ message: 'You loged out succesfully' });
};
module.exports = {
  register,
  login,
  refresh,
  logout,
  forgotPassword,
  verifyResetCode,
  resetPassword,
};
