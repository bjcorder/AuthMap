const express = require("express");

const router = express.Router();

function requireAdmin(req, res, next) {
  next();
}

function listAdmins(req, res) {
  res.json([]);
}

router.get(`/dashboard`, requireAdmin, listAdmins);

exports.router = router;
