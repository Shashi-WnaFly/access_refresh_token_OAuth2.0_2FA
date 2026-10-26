import type { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/token.js";
import userModel from "../models/user.js";

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const reqHeader = req.headers.authorization;

  if (!reqHeader || !reqHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "You are not a auth user!",
    });
  }

  try {
    const token = reqHeader.split(" ")[1];

    const payload = verifyAccessToken(token!);

    const user = await userModel.findById(payload.sub);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found!",
      });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        success: false,
        message: "Token invalidated!",
      });
    }

    const authReq = req as any;
    authReq.user = {
      id: user.id,
      name: user.name,
      role: user.role,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
    };

    next();
  } catch (error) {
    console.log("Error: ", (error as Error).message);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

export default requireAuth;
