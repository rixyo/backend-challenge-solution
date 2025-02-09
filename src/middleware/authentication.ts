import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { redisClient } from "../utils/redis";
import { ERROR_MESSAGES } from "../constants/messages";

interface AuthenticatedRequest extends Request {
  user?: { id: string };
}
export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    if (!process.env.ACCESS_TOKEN_SECRET) {
      throw new Error("JWT_SECRET is not defined in environment variables.");
    }

    // Check if the token is blacklisted
    const isBlacklisted = await redisClient.get(`invalidated:${token}`);
    if (isBlacklisted) {
      res.status(401).json({ message: ERROR_MESSAGES.UNAUTHORIZED });
      return;
    }

    // Verify the token
    const decoded: { id: string } = jwt.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET!
    ) as { id: string };
    req.user = decoded;
    next(); // Proceed to the next middleware/controller
  } catch (error) {
    res.status(403).json({ message: "Forbidden" });
  }
};
