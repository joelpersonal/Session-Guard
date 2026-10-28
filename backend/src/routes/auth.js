const express = require('express');
const router = express.Router();
const Account = require('../models/account');
const SessionManager = require('../models/session');
const config = require('../config');
const { getRedis } = require('../db/redis');
const { executeTerminateAndNotify } = require('../middleware/actions');

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { email, password, name, recoveryEmail } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const existing = await Account.findByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'Account already exists.' });
    }

    const account = await Account.create({ email, password, name, recoveryEmail });
    res.status(201).json({ message: 'Account registered successfully.', account });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const account = await Account.findByEmail(email);
    if (!account) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const isValid = await Account.verifyPassword(password, account.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Session rotation on login: check if previous cookie exists
    const previousSessionId = req.cookies?.[config.session.cookieName] || req.headers['x-session-id'] || null;

    const clientIp = (
      req.headers['x-test-ip'] ||
      req.headers['x-forwarded-for']?.split(',')[0].trim() ||
      req.headers['x-real-ip'] ||
      req.socket.remoteAddress ||
      '127.0.0.1'
    );

    // Create new rotated session and baseline record B_s
    const { sessionId, sessionData, baseline } = await SessionManager.createSession({
      accountId: account.id,
      clientIp,
      headers: req.headers,
      previousSessionId
    });

    // Set secure cookie
    res.cookie(config.session.cookieName, sessionId, {
      httpOnly: true,
      secure: config.session.cookieSecure,
      sameSite: config.session.cookieSameSite,
      maxAge: config.session.absoluteTimeoutMs,
      path: '/'
    });

    res.json({
      message: 'Login successful.',
      sessionId,
      account: {
        id: account.id,
        email: account.email,
        name: account.name,
        recoveryEmail: account.recovery_email,
        mfaEnabled: account.mfa_enabled
      },
      baseline: {
        ipPrefix: baseline.ipPrefix,
        headerHash: baseline.headerHash
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/logout
router.post('/logout', async (req, res) => {
  try {
    const sessionId = req.cookies?.[config.session.cookieName] || req.headers['x-session-id'];
    if (sessionId) {
      await SessionManager.destroySession(sessionId);
    }
    res.clearCookie(config.session.cookieName, { path: '/' });
    res.json({ message: 'Logged out successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/session
router.get('/session', async (req, res) => {
  try {
    const sessionId = req.cookies?.[config.session.cookieName] || req.headers['x-session-id'];
    if (!sessionId) {
      return res.status(401).json({ error: 'Not authenticated.' });
    }

    const session = await SessionManager.getSession(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Session expired or not found.' });
    }

    const account = await Account.findById(session.accountId);
    const baseline = await SessionManager.getBaseline(sessionId);

    res.json({
      session,
      account,
      baseline: baseline ? {
        ipPrefix: baseline.ipPrefix,
        headerHash: baseline.headerHash,
        requestCount: baseline.requestHistory?.length || 0,
        contextCount: baseline.contextHistory?.length || 0
      } : null
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/step-up
// Verifies password re-entry on Step-Up tier challenge.
// On success: re-baselines B_s.
// On failure: escalates immediately to Terminate+Notify!
router.post('/step-up', async (req, res) => {
  const startTime = Date.now();
  const sessionId = req.cookies?.[config.session.cookieName] || req.headers['x-session-id'];
  const { challengeToken, password } = req.body;

  if (!sessionId || !challengeToken || !password) {
    return res.status(400).json({ error: 'Missing challengeToken or password.' });
  }

  const redis = getRedis();
  const rawChallenge = await redis.get(`step_up_challenge:${sessionId}`);
  if (!rawChallenge) {
    return res.status(400).json({ error: 'No active challenge found for this session.' });
  }

  let challenge;
  try {
    challenge = JSON.parse(rawChallenge);
  } catch {
    return res.status(400).json({ error: 'Invalid challenge data.' });
  }

  if (challenge.token !== challengeToken) {
    return res.status(403).json({ error: 'Invalid challenge token.' });
  }

  const account = await Account.findById(challenge.accountId);
  if (!account) {
    return res.status(404).json({ error: 'Account not found.' });
  }

  const isValid = await Account.verifyPassword(password, account.password_hash);
  if (!isValid) {
    // Failure escalates immediately to Terminate+Notify!
    await redis.del(`step_up_challenge:${sessionId}`);
    return executeTerminateAndNotify({
      req,
      res,
      account,
      sessionId,
      mode: 'session-guard',
      riskScore: 1.0,
      signals: challenge.signals,
      reason: 'Step-Up challenge failed: incorrect password provided.',
      startTime
    });
  }

  // Success: Clear challenge and rebaseline B_s to current context
  await redis.del(`step_up_challenge:${sessionId}`);

  const clientIp = (
    req.headers['x-test-ip'] ||
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    '127.0.0.1'
  );

  const ipPrefix = SessionManager.extractIpPrefix(clientIp);
  const headerHash = SessionManager.hashClientHeaders(req.headers);
  const now = Date.now();

  const newBaseline = {
    ip: clientIp,
    ipPrefix,
    userAgent: req.headers['user-agent'] || '',
    headerHash,
    createdAt: now,
    lastRequestAt: now,
    timing: { intervals: [], meanInterval: 0, varianceInterval: 0 },
    requestHistory: [{ path: '/api/auth/step-up', method: 'POST', timestamp: now }],
    sensitiveHistory: [],
    contextHistory: [
      {
        contextId: `${ipPrefix}__${headerHash}`,
        ip: clientIp,
        ipPrefix,
        headerHash,
        timestamp: now
      }
    ]
  };

  await SessionManager.saveBaseline(sessionId, newBaseline);

  res.json({
    message: 'Step-Up verification succeeded. Context re-baselined.',
    verified: true,
    newBaseline: { ipPrefix, headerHash }
  });
});

module.exports = router;

