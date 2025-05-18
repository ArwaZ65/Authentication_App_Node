const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");

router.route("/register").post(authController.register);
router.route("/login").post(authController.login);
router.route("/refresh").get(authController.refresh);//refresh update token
router.route("/logout").post(authController.logout);//post as I sent token
// Password reset routes
router.route("/forgot-password").post(authController.forgotPassword);
router.route("/verify-reset-code").post(authController.verifyResetCode);
router.route("/reset-password/:token").patch(authController.resetPassword);
module.exports = router;
