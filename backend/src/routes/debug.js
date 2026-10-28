const express = require('express');
const router = express.Router();
const config = require('../config');
const { getPool } = require('../db/postgres');
const { getRedis } = require('../db/redis');
const Account = require('../models/account');
const { clearDeliveredMessages } = require('../services/mailSink');

// GET /api/debug/config
router.get('/config', (req, res) => {
  res.json({
    weights: config.weights,
    thresholds: config.thresholds,
    defaultMode: config.defaultMode
  });
});

// POST /api/debug/config
// Dynamic tuning for calibration (used by experiment harness calibrator)
router.post('/config', (req, res) => {
  const { weights, thresholds, defaultMode } = req.body;
  if (weights) {
    config.weights = { ...config.weights, ...weights };
  }
  if (thresholds) {
    config.thresholds = { ...config.thresholds, ...thresholds };
  }
  if (defaultMode) {
    config.defaultMode = defaultMode;
  }
  res.json({
    message: 'Configuration updated successfully.',
    weights: config.weights,
    thresholds: config.thresholds,
    defaultMode: config.defaultMode
  });
});

// GET /api/debug/audit-logs
router.get('/audit-logs', async (req, res) => {
  try {
    const pool = getPool();
    const result = await pool.query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 500');
    res.json({ count: result.rows.length, auditLogs: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/debug/seed
// Seed accounts for calibration and evaluation partitions
router.post('/seed', async (req, res) => {
  try {
    const { accounts } = req.body;
    if (!Array.isArray(accounts)) {
      return res.status(400).json({ error: 'Accounts array is required.' });
    }

    const created = [];
    for (const acc of accounts) {
      const existing = await Account.findByEmail(acc.email);
      if (!existing) {
        const item = await Account.create(acc);
        created.push(item);
      } else {
        // Reset password to default test password so trials remain idempotent
        await Account.updatePassword(existing.id, acc.password);
        created.push(existing);
      }
    }

    res.json({ message: `Seeded ${created.length} accounts.`, accounts: created });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/debug/reset
router.post('/reset', async (req, res) => {
  try {
    const redis = getRedis();
    await redis.flushall();
    clearDeliveredMessages();

    const pool = getPool();
    await pool.query('DELETE FROM audit_logs');
    await pool.query('DELETE FROM notifications');

    res.json({ message: 'Redis flushed, mail sink cleared, and audit logs reset.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
