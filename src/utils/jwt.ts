import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET!;

export const generateAccessToken = (userId: string): string => {
  if (!process.env.ACCESS_TOKEN_SECRET) {
    throw new Error("JWT_SECRET is not defined in environment variables.");
  }
  return jwt.sign(
    {
      id: userId,
      timestamp: Date.now(),
    },
    ACCESS_TOKEN_SECRET,
    { expiresIn: "30m" }
  );
};

export const generateRefreshToken = (userId: string): string => {
  if (!process.env.REFRESH_TOKEN_SECRET) {
    throw new Error(
      "REFRESH_TOKEN_SECRET is not defined in environment variables."
    );
  }
  return jwt.sign(
    {
      id: userId,
      timestamp: Date.now(),
    },
    REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );
};

export const verifyToken = (
  token: string,
  secret: string
): string | jwt.JwtPayload => {
  const to = jwt.verify(token, secret);
  console.log(to, "token");
  return jwt.verify(token, secret);
};
