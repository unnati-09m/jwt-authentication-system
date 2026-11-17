
import express from "express";

import {
  signup,
  login,
  getMe,
  getDashboard
} from "../controllers/authController.js";

import { requireAuth } from "../middleware/requireAuth.js";

const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);

router.get("/me", requireAuth, getMe);
router.get("/dashboard", requireAuth, getDashboard);

export default router;
