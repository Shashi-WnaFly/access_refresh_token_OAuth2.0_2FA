import jwt from "jsonwebtoken";
import config from "../config/config.js";

export function createAccessToken(
  userId: string,
  role: "user" | "admin",
  tokenVersion: number,
) {
  const payload = { sub: userId, role, tokenVersion };
  return jwt.sign(payload, config.JWT_SECRET, { expiresIn: "30m" });
}

export function verifyAccessToken(token: string) {
  return jwt.verify(token, config.JWT_SECRET) as {
    sub: string;
    role: string;
    tokenVersion: number;
  };
}

export function createRefreshToken(userId: string, tokenVersion: number) {
  const payload = { sub: userId, tokenVersion };
  return jwt.sign(payload, config.JWT_SECRET, { expiresIn: "7d" });
}

export function verifyRefreshToken(token: string) {
  return jwt.verify(token, config.JWT_SECRET) as {
    sub: string;
    tokenVersion: number;
  };
}
