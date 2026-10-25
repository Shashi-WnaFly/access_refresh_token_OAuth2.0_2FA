import type { Request, Response } from "express";
import userModel from "../../models/user.js";
import { success, z } from "zod";
import jwt from "jsonwebtoken";
import { isStrongPasswordSchema, loginSchema, registerSchema } from "./auth.schema.js";
import { compareHash, passwordHash } from "../../lib/hash.js";
import { SendEmail } from "../../lib/email.js";
import config from "../../config/config.js";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
} from "../../lib/token.js";
import crypto from "crypto";

function getAppUrl() {
  return config.APP_URL || `http://localhost:${config.PORT}`;
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: `Invalid data! error: ${z.flattenError(result.error)}`,
      });
    }

    const { name, email, password } = result.data;

    const isUserExists = await userModel.findOne({ email });

    if (isUserExists) {
      return res.status(400).json({
        success: false,
        message: "Email is already in use. try with a different email.",
      });
    }

    const passwordHashed = await passwordHash(password);

    const savedUser = await userModel.create({
      name,
      email,
      passwordHash: passwordHashed,
    });

    const verifyToken = jwt.sign(
      { sub: savedUser._id },
      process.env.JWT_SECRET!,
      { expiresIn: "1d" },
    );

    const verifyUrl = `${getAppUrl()}/api/auth/verify-email?token=${verifyToken}`;

    await SendEmail(
      savedUser.email,
      "Verify your email",
      `<p>please verify your email by clicking this link : </p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>`,
    );

    res.status(201).json({
      status: "success",
      message: "Registration is successfully done.",
      user: {
        id: savedUser._id,
        name: savedUser.name,
        email: savedUser.email,
        isEmailVerified: savedUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.log("Error : ", (error as Error).message);
    return res.status(500).json({
      success: false,
      message: "Interval server error.",
    });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = (req.query.token as string) || undefined;

  if (!token)
    return res.status(400).json({
      success: false,
      message: "Verification token is missing",
    });

  try {
    const payload = jwt.verify(token, config.JWT_SECRET!) as {
      sub: string;
    };

    if (!payload) {
      return res.status(400).json({
        success: false,
        message: "Verification token is invalid or expired",
      });
    }

    const user = await userModel.findById(payload.sub);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found!",
      });
    }

    if (user.isEmailVerified) {
      return res.status(400).json({
        success: true,
        message: "Your email already verified",
      });
    }

    user.isEmailVerified = true;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Email is now verified! you can login",
    });
  } catch (error) {
    console.log("Error: ", (error as Error).message);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: `Invalid data! error: ${z.flattenError(result.error)}`,
      });
    }

    const { email, password } = result.data;

    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: `Credentials are invalid!`,
      });
    }

    if (!user.isEmailVerified) {
      return res.status(400).json({
        success: false,
        message: `Verify your email first then try loggin in...`,
      });
    }

    if (!compareHash(password, user.passwordHash)) {
      return res.status(400).json({
        success: false,
        message: `Credentials are invalid!`,
      });
    }

    const accessToken = createAccessToken(
      user._id.toString(),
      user.role,
      user.tokenVersion,
    );

    const refreshToken = createRefreshToken(
      user._id.toString(),
      user.tokenVersion,
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: config.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      success: true,
      message: "User logged in successfully",
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
        name: user.name,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log("Error: ", (error as Error).message);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

export async function refreshHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Refresh token is missing",
      });
    }

    const payload = verifyRefreshToken(token);

    if (!payload) {
      return res.status(401).json({
        success: false,
        message: "Refresh token is invalid!",
      });
    }

    const user = await userModel.findById(payload.sub);

    if (!user || user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({
        success: false,
        message: "Refresh token is invalidated!",
      });
    }

    const newAccessToken = createAccessToken(
      user._id.toString(),
      user.role,
      user.tokenVersion,
    );
    const newRefreshToken = createRefreshToken(
      user._id.toString(),
      user.tokenVersion,
    );

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: config.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      success: true,
      message: "Token refreshed",
      accessToken: newAccessToken,
      user: {
        id: user._id,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
        name: user.name,
        role: user.role,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.log("Error: ", (error as Error).message);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

export function logoutHandler(_req: Request, res: Response) {
  res.clearCookie("refreshToken", { path: "/" });
  res.status(200).json({
    success: true,
    message: "Logged out",
  });
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  const { email } = req.body as { email: string };
  const normalizeEmail = email.trim().toLowerCase();

  if (!normalizeEmail) {
    return res.status(400).json({
      success: true,
      message: "Email is missing or invalid!",
    });
  }

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(200).json({
        success: true,
        message:
          "If an account with this email exists, we will send you a reset link",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");

    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    const resetLink = `${getAppUrl()}/api/auth/reset-password?token=${rawToken}`;

    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();

    await SendEmail(
      email,
      "Reset your password",
      `
      <p>You requested password reset. Click on the below link to reset the password</p>
      <p><a href="${resetLink}">${resetLink}</a></p>`,
    );

    res.status(200).json({
      success: true,
      message:
        "If an account with this email exists, we will send you a reset link",
    });
  } catch (error) {
    console.log("Error: ", (error as Error).message);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  const { token, password } = req.body as { token?: string; password: string };

  if (!token || !password) {
    return res.status(400).json({
      success: true,
      message: "token or password is missing",
    });
  }

  try {
    const isStrongPassword = isStrongPasswordSchema.safeParse({password});

    if (!isStrongPassword.success) {
      return res.status(400).json({
        success: false,
        message: "Password should be strong",
      });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await userModel.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Reset token is invalid or expired!",
      });
    }

    user.passwordHash = await passwordHash(password);
    user.resetPasswordExpires = null;
    user.resetPasswordToken = null;
    user.tokenVersion = user.tokenVersion + 1;

    await user.save();

    res.status(200).json({
      success: true,
      message: "Your password reset successfully",
    });
  } catch (error) {
    console.log("Error: ", (error as Error).message);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}

