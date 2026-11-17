import jwt from "jsonwebtoken";

export const requireAuth = (req, res, next) => {
  try {
    // 1. Get Authorization header
    const authHeader = req.headers.authorization;

    // 2. Check if token exists and uses Bearer format
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Access denied. Token missing.",
      });
    }

    // 3. Extract token
    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        message: "Access denied. Token missing.",
      });
    }

    // 4. Verify JWT
    const decoded = jwt.verify(token, process.env.JWTSECRET);

    // 5. Attach decoded data to request
    req.user = decoded;

    // 6. Allow request to continue
    next();

  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired token",
    });
  }
};
