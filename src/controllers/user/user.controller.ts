import type { Request, Response } from "express";

export function getMeHandler(req: Request, res: Response) {
  const authReq = req as any;
  res.status(200).json({
    success: true,
    user: authReq.user,
  });
}
