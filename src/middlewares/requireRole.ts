import type { NextFunction, Request, Response } from "express";

function requireRole(role: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const reqAuth = req as any;
    const reqUser = reqAuth.user;

    if (!reqUser) {
      return res.status(401).json({
        success: true,
        message: "You are not a auth user. Invalid request.",
      });
    }

    if (reqUser.role !== role) {
      return res.status(403).json({
        success: false,
        message: "Request forbidden",
      });
    }

    next();
  };
}

export default requireRole;
