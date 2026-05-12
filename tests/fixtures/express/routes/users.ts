import express from "express";

const router = express.Router();

function requireUser(req: express.Request, res: express.Response, next: express.NextFunction) {
  next();
}

function requireTenant(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (req.user?.tenantId !== req.params.tenantId) {
    return res.sendStatus(403);
  }
  next();
}

const updateUser = (req: express.Request, res: express.Response) => {
  res.json({});
};

router
  .route("/:userId")
  .get(requireUser, (req: express.Request, res: express.Response) => {
    res.json({});
  })
  .post(requireUser, updateUser);

router.get("/:tenantId/settings", requireTenant, (req: express.Request, res: express.Response) => {
  res.json({ tenantId: req.params.tenantId });
});

export default router;
