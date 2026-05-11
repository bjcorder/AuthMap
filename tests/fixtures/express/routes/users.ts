import express from "express";

const router = express.Router();

function requireUser(req: express.Request, res: express.Response, next: express.NextFunction) {
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

export default router;
