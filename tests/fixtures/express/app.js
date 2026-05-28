const express = require("express");
const usersRouter = require("./routes/users");
const adminRouter = require("./routes/admin").router;
const { router: exportedRouter } = require("./routes/exported");

const app = express();
const localRouter = express.Router();
const childRouter = express.Router();
const dynamicPrefix = "/dynamic";
const dynamicPath = "/generated";
const routeFactories = {};
const indexedRouteFactories = {};

function requireAuth(req, res, next) {
  next();
}

function requireRole(role) {
  return function roleGuard(req, res, next) {
    if (req.user?.role !== role) {
      return res.sendStatus(403);
    }
    next();
  };
}

function requirePermission(permission) {
  return function permissionGuard(req, res, next) {
    if (!req.user?.permissions?.includes(permission)) {
      return res.sendStatus(403);
    }
    next();
  };
}

function audit(req, res, next) {
  next();
}

function publicRoute(req, res, next) {
  next();
}

function dynamicPolicyCheck(name) {
  return name === "accounts.update";
}

function listAccounts(req, res) {
  res.json([]);
}

$.get(config.relative_path + "/api/accounts", function () {});
api.put("/accounts/" + accountId, { enabled: true });

app.all("/admin", requireAuth, requirePermission("admin.access"));

app.get("/health", requireAuth, (req, res) => {
  res.json({ ok: true });
});

app.get("/public/status", publicRoute, listAccounts);
app.get("/conflicting", publicRoute, requireAuth, listAccounts);
app.post("/accounts", [requireAuth, audit], listAccounts);
app.post("/admin/jobs", requireAuth, requireRole("admin"), listAccounts);
app.get(`/${tenant}/reports`, requireAuth, listAccounts);
app.patch("/accounts/:id/permissions", requirePermission("accounts.write"), (req, res) => {
  if (!dynamicPolicyCheck("accounts.update")) {
    return res.sendStatus(403);
  }
  res.sendStatus(204);
});
app.delete(dynamicPath, requireAuth, listAccounts);
if (false) {
  app.get("/unreachable/admin", requireAuth, listAccounts);
}

localRouter.put("/:id", requireAuth, listAccounts);
childRouter.get("/child", audit, listAccounts);
localRouter.use("/nested", requireAuth, childRouter);
localRouter.use("/loop", localRouter);

routeFactories.mapped = (router, prefix) => {
  router.get(`/${prefix}/factory`, requireAuth, listAccounts);
};
routeFactories.mapped(localRouter, "mapped");

indexedRouteFactories.indexed = (router, prefix) => {
  router.get(`/${prefix}/indexed`, requireAuth, listAccounts);
};
const selectedFactory = "indexed";
indexedRouteFactories[selectedFactory](localRouter, "mapped");

app.use("/api", localRouter);
app.use("/secure", requireAuth, usersRouter);
app.use("/v1", usersRouter);
app.use("/admin", adminRouter);
app.use("/exported", exportedRouter);
app.use(dynamicPrefix, childRouter);
app.use("/missing", missingRouter);

module.exports = app;
