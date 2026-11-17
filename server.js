
import express from "express";
import "dotenv/config";
import authRoutes from "./src/routes/authRoutes.js";

const app = express();

app.use(express.json());

app.use("/", authRoutes);

app.get("/", (req, res) => {
  res.send("JWT Authentication Server is running!");
});

const PORT = 3000;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
