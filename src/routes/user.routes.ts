import express, { type Request, type Response } from "express";
import requireAuth from "../middlewares/requireAuth.js";
import * as userRouter from "../controllers/user/user.controller.js"

const router = express.Router();

router.get("/me", requireAuth, userRouter.getMeHandler);

export default router;
