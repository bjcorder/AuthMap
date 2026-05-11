const express = require("express");
const usersRouter = require("./routes/users");
const adminRouter = require("./routes/admin").router;
const { router: exportedRouter } = require("./routes/exported");

const app = express();
const localRouter = express.Router();
const childRouter = express.Router();
const dynamicPrefix = "/dynamic";
const dynamicPath = "/generated";

function requireAuth(req, res, next) {
  next();
}

function audit(req, res, next) {
  next();
}

function listAccounts(req, res) {
  res.json([]);
}

app.get("/health", requireAuth, (req, res) => {
  res.json({ ok: true });
});

app.post("/accounts", [requireAuth, audit], listAccounts);
app.delete(dynamicPath, requireAuth, listAccounts);

localRouter.put("/:id", requireAuth, listAccounts);
childRouter.get("/child", audit, listAccounts);
localRouter.use("/nested", childRouter);
localRouter.use("/loop", localRouter);

app.use("/api", localRouter);
app.use("/secure", requireAuth, usersRouter);
app.use("/v1", usersRouter);
app.use("/admin", adminRouter);
app.use("/exported", exportedRouter);
app.use(dynamicPrefix, childRouter);
app.use("/missing", missingRouter);

module.exports = app;
