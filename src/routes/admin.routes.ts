import express from "express";
import requireAuth from "../middlewares/requireAuth.js";
import requireRole from "../middlewares/requireRole.js";
import * as adminRouter from "../controllers/admin/admin.controller.js";

const router = express.Router();

router.get("/users", requireAuth, requireRole("admin"), adminRouter.getUsers);

export default router;
