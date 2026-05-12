import express from "express";
import { createSession } from "./express_service";
import { PrismaClient } from "@prisma/client";

const app = express();
const prisma = new PrismaClient();

function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  next();
}

app.post("/express/direct", requireAuth, async (req: express.Request, res: express.Response) => {
  await prisma.user.update({
    where: { id: req.body.userId },
    data: { disabled: true },
  });
  res.json({ ok: true });
});

app.post("/express/service", requireAuth, async function expressService(req: express.Request, res: express.Response) {
  await createSession(req.body.userId);
  res.json({ ok: true });
});

app.post("/express/dynamic", requireAuth, (req: express.Request, res: express.Response) => {
  return serviceClient.deleteUser(req.params.userId);
});

app.get("/express/read", (req: express.Request, res: express.Response) => {
  res.json({ ok: true });
});

export default app;

