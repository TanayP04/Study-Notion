const bcrypt = require("bcryptjs");
const User = require("../models/User");
const OTP = require("../models/OTP");
const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const mailSender = require("../utils/mailSender");
const { passwordUpdated } = require("../mail/templates/passwordUpdate");
const Profile = require("../models/Profile");
require("dotenv").config();

// Signup Controller for Registering Users
exports.signup = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      confirmPassword,
      accountType,
      contactNumber,
      otp,
    } = req.body;

    if (
      !firstName ||
      !lastName ||
      !email ||
      !password ||
      !confirmPassword ||
      !otp ||
      !accountType
    ) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Password and Confirm Password do not match",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "User already exists. Please sign in to continue.",
      });
    }

    // Get the latest OTP for this email
    const otpRecord = await OTP.find({ email }).sort({ createdAt: -1 }).limit(1);
    if (otpRecord.length === 0 || otp !== otpRecord[0].otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Correct approved assignment
    const approved = accountType === "Instructor" ? false : true;

    // Create profile
    const profileDetails = await Profile.create({
      gender: null,
      dateOfBirth: null,
      about: null,
      contactNumber: contactNumber || null,
    });

    const user = await User.create({
      firstName,
      lastName,
      email,
      contactNumber: contactNumber || null,
      password: hashedPassword,
      accountType,
      approved,
      additionalDetails: profileDetails._id,
      image: "", // You may want to set a default image URL here if you want
    });

    return res.status(201).json({
      success: true,
      user,
      message: "User registered successfully",
    });
  } catch (error) {
    console.error("Signup error:", error);
    return res.status(500).json({
      success: false,
      message: "User cannot be registered. Please try again.",
    });
  }
};

// Login controller for authenticating users
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please fill all the required fields",
      });
    }

    const user = await User.findOne({ email }).populate("additionalDetails");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not registered. Please sign up first.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Password is incorrect",
      });
    }

    const token = jwt.sign(
      { email: user.email, id: user._id, role: user.accountType },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    user.token = token;
    user.password = undefined;

    const cookieOptions = {
      expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
      httpOnly: true,
    };

    res.cookie("token", token, cookieOptions).status(200).json({
      success: true,
      token,
      user,
      message: "User login success",
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      success: false,
      message: "Login failure. Please try again.",
    });
  }
};

// Send OTP For Email Verification
exports.sendotp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(409).json({
        success: false,
        message: "User is already registered",
      });
    }

    // Generate unique OTP (numeric only)
    let otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
      digits: true,
    });

    // Ensure OTP is unique by checking DB (very rare collisions)
    let existingOtp = await OTP.findOne({ otp });
    while (existingOtp) {
      otp = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
        digits: true,
      });
      existingOtp = await OTP.findOne({ otp });
    }

    const otpPayload = { email, otp };
    const otpBody = await OTP.create(otpPayload);

    // TODO: Send OTP via email using mailSender utility here

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully",
      otp, // Ideally do NOT send OTP in response in production; just for dev/testing
    });
  } catch (error) {
    console.error("Send OTP error:", error);
    return res.status(500).json({
      success: false,
      message: "Error sending OTP",
      error: error.message,
    });
  }
};

// Controller for Changing Password
exports.changePassword = async (req, res) => {
  try {
    const userDetails = await User.findById(req.user.id);

    if (!userDetails) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Old password and new password are required",
      });
    }

    const isPasswordMatch = await bcrypt.compare(oldPassword, userDetails.password);

    if (!isPasswordMatch) {
      return res.status(401).json({
        success: false,
        message: "The old password is incorrect",
      });
    }

    const encryptedPassword = await bcrypt.hash(newPassword, 10);
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { password: encryptedPassword },
      { new: true }
    );

    // Send notification email about password update
    try {
      const emailResponse = await mailSender(
        updatedUser.email,
        "Password for your account has been updated",
        passwordUpdated(
          updatedUser.email,
          `Password updated successfully for ${updatedUser.firstName} ${updatedUser.lastName}`
        )
      );
      console.log("Password update email sent:", emailResponse.response);
    } catch (mailError) {
      console.error("Error sending password update email:", mailError);
      // Don't fail the request if email sending fails, but log it
    }

    return res.status(200).json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.error("Change password error:", error);
    return res.status(500).json({
      success: false,
      message: "Error occurred while updating password",
      error: error.message,
    });
  }
};
