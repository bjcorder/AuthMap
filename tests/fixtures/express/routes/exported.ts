import express from "express";

export const router = express.Router();

function audit(req: express.Request, res: express.Response, next: express.NextFunction) {
  next();
}

function exportAudit(req: express.Request, res: express.Response) {
  res.json({ ok: true });
}

router.patch("/audit", audit, exportAudit);
