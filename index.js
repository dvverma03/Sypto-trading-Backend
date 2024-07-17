const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const CookieParser = require("cookie-parser");
const { DATABASE_NAME } = require("./src/constants.js");
require("dotenv").config();
const User = require("./src/models/user.model.js");
const nodemailer = require('nodemailer');
const app = express();
app.use(express.json());
app.use(
  cors()
);


const connectToDatabase = async () => {
  try {
    await mongoose.connect(process.env.DATABASE_URL, {
      autoIndex: true,
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`MongoDB connected! DB HOST: ${mongoose.connection.host}`);
  } catch (err) {
    console.error("MongoDB connection failed", err);
    process.exit(1);
  }
};

connectToDatabase();

let Otp=null;

app.post("/register", async (req, res) => {
    try {
      const {email } = req.body;
      console.log("email", email)

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: "User already exists" });
      }
  
      // Create a transporter object
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST, 
        port: process.env.SMTP_PORT, 
        secure: false, 
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      });
  
      // Generate a random OTP
       Otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  
      // Configure the mail options object
      const mailOptions = {
        from: '"Deepak Verma" <dvverma9211@gmail.com>', // Sender address
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code for registration is ${Otp}.`,
      };
  
  
      // Send the OTP email
      await transporter.sendMail(mailOptions);
  
      res.status(200).json({
        status: "ok",
        message: `OTP sent to your email ${email}. Please verify to otp complete registration.`,
      });
    } catch (err) {
      console.error("Error during registration:", err);
      res.status(500).json({ error: "Internal server error" });
    }
});
  
app.post("/verify-otp-register", async (req, res) => {
    try {
      const { fullName,email, UserOtp, password } = req.body;
      if (UserOtp != Otp) {
        return res.status(400).json({ error: "Invalid or expired OTP" });
      }
      const hash = await bcrypt.hash(password, 10);
  
      // Create the new user
      const newUser = await User.create({
        fullName:fullName,
        email:email,
        password: hash,
      });

      console.log("new user", newUser)
  
      res.status(200).json({
        status: "User created successfully",
        user: newUser._id,
        fullName:newUser.fullName
      });
    } catch (err) {
      console.error("Error during OTP verification:", err);
      res.status(500).json({ error: "Internal server error",err });
    }
});

app.post("/login",async (req, res) => {
  try{
      const { email, password } = req.body;
      const user=await User.findOne({email})
      if (!user) {
        return res.status(400).json({ error: "User not exist" });
      }

      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return res.status(500).json({ error: "Internal server error" });
        }

        if (!isMatch) {
          return res.status(402).json({ error: "Password is incorrect" });
        }
      });

      // Create a transporter object
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST, 
        port: process.env.SMTP_PORT, 
        secure: false, 
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      });
  
      // Generate a random OTP
       Otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  
      // Configure the mail options object
      const mailOptions = {
        from: '"Deepak Verma" <dvverma9211@gmail.com>', // Sender address
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code for registration is ${Otp}.`,
      };
  
      // Send the OTP email
      await transporter.sendMail(mailOptions);
  
      res.status(200).json({
        status: "ok",
        message: `OTP sent to your email ${email}. Please verify to otp complete registration.`,
      });
    }
    catch(err ) {
      console.error("Error finding user:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
});

app.post("/verify-otp-login", async (req, res) => {
  try {
    const {email, UserOtp } = req.body;

    // Check if OTP is correct and not expired
    if (UserOtp != Otp) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

     const user= await User.findOne({email}) 
     if(!user) return res.status(400).json({error:"User not exist"})
      res.status(200).json({
        status: "User logged in successfully",
        user: user._id,
        fullName:user.fullName
      });
  } catch (err) {
    console.error("Error during OTP verification:", err);
    res.status(500).json({ error: "Internal server error",err });
  }
});

app.post("/logout", (req, res) => {
  const { token1 } = req.body;
  User.findOne({ token: token1 }).then((user) => {
    if (user) {
      const token2 = Math.random() + new Date();
      User.findByIdAndUpdate(user._id, { token: token2 }, { new: true })
        .then((updatedUser) => {
          return res.json(updatedUser);
        })
        .catch((err) => {
          console.error("Error updating token:", err);
          return res.status(500).json({ error: "Internal server error" });
        });
    } else {
      return res.json("Password is incorrect");
    }
  });
});

app.post("/userInfo", (req, res) => {
  const { userId } = req.body;
  User.findOne({ _id: userId }).then((user) => {
    console.log("user info",user);
    if (user) {
      return res.json(user);
    } else {
      return res.json("Password is incorrect");
    }
  });
});

app.listen(1234, () => {
  console.log(`server is running at port${1234}`);
});
