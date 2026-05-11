const express = require("express");

const router = express.Router();

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

router.get("/me", requireAuth, (req, res) => {
  res.json(req.user);
});

router.post("/admin/jobs", requireAuth, requireRole("admin"), (req, res) => {
  res.sendStatus(202);
});

module.exports = router;
