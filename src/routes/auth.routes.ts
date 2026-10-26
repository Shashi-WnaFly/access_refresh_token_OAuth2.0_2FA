import express from "express";
import * as authRouter from "../controllers/auth/auth.controller.js";
import requireAuth from "../middlewares/requireAuth.js";
const router = express.Router();

router.post("/register", authRouter.registerHandler);
router.post("/login", authRouter.loginHandler);
router.get("/verify-email", authRouter.verifyEmailHandler);
router.post("/refresh", authRouter.refreshHandler);
router.post("/logout", authRouter.logoutHandler);
router.post("/forgot-password", authRouter.forgotPasswordHandler);
router.post("/reset-password", authRouter.resetPasswordHandler);
router.get("/google", authRouter.googleAuthStartHandler);
router.get("/google/callback", authRouter.googleAuthCallbackHandler);
router.post("/2fa/setup", requireAuth, authRouter.twoFASetupHandler);
router.post("/2fa/verify", requireAuth, authRouter.twoFAVerifyHandler);

export default router;
