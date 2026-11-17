
import { prisma } from "../config/prisma.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

export const signup = async (req, res) => {
  try {
    // 1. Get email and password
    const { email, password, name } = req.body;

    // 2. Validate input
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.trim() === "" ||
      password.trim() === ""
    ) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must contain at least 6 characters",
      });
    }

    // 3. Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    // 4. Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: {
        email: normalizedEmail,
      },
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Email already registered",
      });
    }

    // 5. Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 6. Create user in database
    const user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        name: typeof name === "string" && name.trim()
          ? name.trim()
          : null,
      },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    // 7. Generate JWT token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      process.env.JWTSECRET,
      {
        expiresIn: "1h",
        jwtid: randomUUID(),
      }
    );

    // 8. Send response
    return res.status(201).json({
      message: "Registration successful",
      user,
      token,
    });

  } catch (error) {
    console.error("Signup Error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
};


export const login = async (req, res) => {
  try {
    // 1. Get email and password
    const { email, password } = req.body;

    // 2. Validate input
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      email.trim() === "" ||
      password.trim() === ""
    ) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    // 3. Normalize email
    const normalizedEmail = email.trim().toLowerCase();

    // 4. Find user in database
    const user = await prisma.user.findUnique({
      where: {
        email: normalizedEmail,
      },
    });

    // 5. Check password
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    // 6. Generate JWT
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
      },
      process.env.JWTSECRET,
      {
        expiresIn: "1h",
        jwtid: randomUUID(),
      }
    );

    // 7. Return response
    return res.status(200).json({
      message: "Login successful",
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt,
      },
      token,
    });

  } catch (error) {
    console.error("Login Error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
};


export const getMe = async (req, res) => {
  try {
    // Find authenticated user
    const user = await prisma.user.findUnique({
      where: {
        id: req.user.id,
      },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    // Check if user exists
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Return user profile
    return res.status(200).json({
      message: "User profile fetched successfully",
      user,
    });

  } catch (error) {
    console.error("Get Profile Error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
};


export const getDashboard = async (req, res) => {
  try {
    // Find authenticated user
    const user = await prisma.user.findUnique({
      where: {
        id: req.user.id,
      },
      select: {
        email: true,
        name: true,
      },
    });

    // Check if user exists
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Use name or email for welcome message
    const welcomeName = user.name || user.email;

    return res.status(200).json({
      message: `Welcome to your dashboard, ${welcomeName}!`,
      user: {
        email: user.email,
        name: user.name,
      },
    });

  } catch (error) {
    console.error("Dashboard Error:", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
};
