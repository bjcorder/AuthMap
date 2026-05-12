import express from "express";
import accountsRouter from "./routes/accounts";

const app = express();
const dynamicPrefix = "/dynamic";

export function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  next();
}

export function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (req.user?.role !== "admin") {
    return res.sendStatus(403);
  }
  next();
}

export function requirePermission(permission: string) {
  return function permissionGuard(req: express.Request, res: express.Response, next: express.NextFunction) {
    if (!req.user?.permissions?.includes(permission)) {
      return res.sendStatus(403);
    }
    next();
  };
}

export function requireTenant(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (req.user?.tenantId !== req.params.tenantId) {
    return res.sendStatus(403);
  }
  next();
}

export function audit(req: express.Request, res: express.Response, next: express.NextFunction) {
  next();
}

app.get("/health", (req: express.Request, res: express.Response) => {
  res.json({ ok: true });
});

app.use("/api", requireAuth, accountsRouter);
app.use(dynamicPrefix, accountsRouter);
app.use("/missing", missingRouter);

export default app;
