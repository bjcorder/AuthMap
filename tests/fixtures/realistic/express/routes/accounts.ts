import express from "express";
import { PrismaClient } from "@prisma/client";
import { audit, requireAdmin, requireAuth, requirePermission, requireTenant } from "../app";
import { createAccount, deleteAccount, updateAccount } from "../services/accounts";

const prisma = new PrismaClient();
const router = express.Router();

function dynamicPolicyCheck(name: string) {
  return name === "accounts.update";
}

router.get("/:accountId", requireAuth, (req: express.Request, res: express.Response) => {
  res.json({ id: req.params.accountId });
});

router.post("/", requireAuth, audit, async (req: express.Request, res: express.Response) => {
  await prisma.account.create({
    data: { ownerId: req.user.id, name: req.body.name },
  });
  res.json({ created: true });
});

router.patch(
  "/:accountId",
  requirePermission("accounts.write"),
  async (req: express.Request, res: express.Response) => {
    if (!dynamicPolicyCheck("accounts.update")) {
      return res.sendStatus(403);
    }
    await updateAccount(req.params.accountId, req.body);
    res.json({ updated: true });
  },
);

router.delete("/:accountId", requireAdmin, async (req: express.Request, res: express.Response) => {
  await deleteAccount(req.params.accountId);
  res.sendStatus(204);
});

router.post("/service", requireAuth, async (req: express.Request, res: express.Response) => {
  await createAccount(req.user.id, req.body.name);
  res.json({ created: true });
});

router.post("/dynamic-service", requireAuth, (req: express.Request, res: express.Response) => {
  return accountServiceClient.create(req.user.id, req.body.name);
});

router.get("/tenant/:tenantId", requireTenant, (req: express.Request, res: express.Response) => {
  res.json({ tenantId: req.params.tenantId });
});

export default router;
