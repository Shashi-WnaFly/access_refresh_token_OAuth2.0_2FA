import type { Request, Response } from "express";
import userModel from "../../models/user.js";

export async function getUsers(_req: Request, res: Response) {
  try {
    const users = await userModel
      .find(
        {},
        {
          email: 1,
          role: 1,
          isEmailVerified: 1,
          createdAt: 1,
        },
      )
      .sort({ createdAt: -1 });

    const result = users.map((u) => ({
      _id: u._id,
      email: u.email,
      role: u.role,
      isEmailVerified: u.isEmailVerified,
      createdAt: u.createdAt,
    }));

    return res.status(200).json({
      success: true,
      users: result,
    });
  } catch (error) {
    console.log("Error: ", (error as Error).message);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
}
