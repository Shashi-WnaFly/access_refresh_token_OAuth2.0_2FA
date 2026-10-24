import express from "express";
import * as authRouter from "../controllers/auth/auth.controller.js";
const router = express.Router();

router.post("/register", authRouter.registerHandler);
router.post("/login", authRouter.loginHandler);
router.get("/verify-email", authRouter.verifyEmailHandler);
router.post("/refresh", authRouter.refreshHandler);
router.post("/logout", authRouter.logoutHandler);
router.post("/forgot-password", authRouter.forgotPasswordHandler);
router.post("/reset-password", authRouter.resetPasswordHandler);

export default router;
