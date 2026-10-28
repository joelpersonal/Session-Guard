const express = require('express');
const router = express.Router();
const sessionGuard = require('../middleware/sessionGuard');
const { getRedis } = require('../db/redis');

// Apply SessionGuard middleware to all user routes
router.use(sessionGuard());

// GET /api/user/profile
router.get('/profile', async (req, res) => {
  res.json({
    account: {
      id: req.account.id,
      email: req.account.email,
      name: req.account.name,
      recoveryEmail: req.account.recovery_email,
      mfaEnabled: req.account.mfa_enabled
    },
    session: {
      id: req.session.sessionId,
      createdAt: req.session.createdAt,
      lastActivityAt: req.session.lastActivityAt
    }
  });
});

// GET /api/user/dashboard
router.get('/dashboard', async (req, res) => {
  const redis = getRedis();
  const sessionIds = await redis.smembers(`user_sessions:${req.account.id}`);

  res.json({
    message: `Welcome back, ${req.account.name || req.account.email}!`,
    activeSessionsCount: sessionIds.length,
    account: {
      email: req.account.email,
      mfaEnabled: req.account.mfa_enabled
    },
    systemMetrics: {
      timestamp: Date.now(),
      serverStatus: 'operational'
    }
  });
});

// GET /api/user/settings
router.get('/settings', async (req, res) => {
  res.json({
    account: {
      email: req.account.email,
      recoveryEmail: req.account.recovery_email,
      mfaEnabled: req.account.mfa_enabled
    },
    securitySettings: {
      multiFactorAuth: req.account.mfa_enabled,
      sessionTimeoutMinutes: 15,
      sessionGuardProtection: 'active'
    }
  });
});

module.exports = router;

