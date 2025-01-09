const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const User = require("./models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 6001;
const SECRET_KEY = process.env.SECRET_KEY;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Connect to MongoDB
require("dotenv").config();

mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.log(err);
  });

app.get("/", (req, res) => {
  res.send("Hello World!");
});

// Signup
app.post("/api/signup", async (req, res) => {
  const { name, email, username, password } = req.body;
  if (!name || !email || !username || !password) {
    return res.status(400).json({ message: "Please fill all the fields" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const newUser = await User({
      name: name,
      email: email,
      username: username,
      password: hashedPassword,
    });
    await newUser.save();
    res.status(201).json({ message: "User Created Successfully" });
  } catch (error) {
    res.status(500).json({ message: "An Error Occured During Signup" });
  }
});

// Signin
app.post("/api/signin", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Please fill all the fields" });
  }

  try {
    const foundUser = await User.findOne({ email: email });
    // Check User
    if (!foundUser) {
      return res.status(400).json({ message: "User Not Found" });
    }
    // Check Password
    const isPasswordCorrect = await bcrypt.compare(password, foundUser.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }

    // Generate Token
    const token = jwt.sign(
      {
        id: foundUser._id,
        name: foundUser.name,
        email: foundUser.email,
        username: foundUser.username,
      },
      SECRET_KEY,
      { expiresIn: "1h" }
    );
    res
      .status(200)
      .json({ message: "User Logged In Successfully", token: token });
  } catch (error) {
    res.status(500).json({ message: "An Error Occured During Signin" });
  }
});

// Protected Route
app.get("/api/protected", (req, res) => {
    const token = req.headers.authorization.split(" ")[1];
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        res.status(200).json({ message: "Protected Route", user: decoded });
    } catch (error) {
        res.status(401).json({ message: "Invalid Token" });
    }
});

// Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
