const config = require('../config');
const SessionManager = require('../models/session');
const Account = require('../models/account');
const { extractNetworkSignal } = require('./signals/network');
const { extractDeviceSignal } = require('./signals/device');
const { extractTemporalSignal, updateTimingState } = require('./signals/temporal');
const { extractSequenceSignal, updateSequenceHistory } = require('./signals/sequence');
const { extractConcurrencySignal, updateContextHistory } = require('./signals/concurrency');
const { extractSensitiveSignal } = require('./signals/sensitive');
const { executeTerminateAndNotify, executeStepUpChallenge } = require('./actions');

/**
 * SessionGuard Core Express Middleware
 */
function sessionGuardMiddleware(options = {}) {
  return async (req, res, next) => {
    const startTime = Date.now();

    // Determine middleware mode: request header override > options > config
    const mode = (
      req.headers['x-session-guard-mode'] ||
      options.mode ||
      config.defaultMode
    ).toLowerCase();

    // 1. Session Identification (Cookie or Header)
    const sessionId = (
      req.cookies?.[config.session.cookieName] ||
      req.headers['x-session-id'] ||
      (req.headers['authorization']?.startsWith('Bearer ') ? req.headers['authorization'].slice(7) : null)
    );

    if (!sessionId) {
      return res.status(401).json({
        error: 'Authentication required. No session identifier provided.',
        code: 'NO_SESSION'
      });
    }

    // 2. Retrieve session from Redis (checks idle & absolute expiration)
    const session = await SessionManager.getSession(sessionId);
    if (!session) {
      res.clearCookie(config.session.cookieName, { path: '/' });
      return res.status(401).json({
        error: 'Session invalid or expired.',
        code: 'SESSION_EXPIRED'
      });
    }

    // 3. Retrieve associated account
    const account = await Account.findById(session.accountId);
    if (!account) {
      await SessionManager.destroySession(sessionId);
      res.clearCookie(config.session.cookieName, { path: '/' });
      return res.status(401).json({
        error: 'Account not found.',
        code: 'ACCOUNT_NOT_FOUND'
      });
    }

    req.session = session;
    req.account = account;

    // 4. Client context extraction (supports X-Test-Ip / X-Forwarded-For for harness)
    const clientIp = (
      req.headers['x-test-ip'] ||
      req.headers['x-forwarded-for']?.split(',')[0].trim() ||
      req.headers['x-real-ip'] ||
      req.socket.remoteAddress ||
      '127.0.0.1'
    );
    const userAgent = req.headers['user-agent'] || '';
    const currentPath = req.originalUrl || req.path;
    const currentMethod = req.method;

    // Retrieve baseline record B_s
    const baseline = await SessionManager.getBaseline(sessionId);

    // ==========================================
    // MODE 1: Token-only
    // ==========================================
    if (mode === 'token-only') {
      res.setHeader('X-Session-Guard-Decision', 'Allow');
      res.setHeader('X-Session-Guard-Mode', 'token-only');
      return next();
    }

    // ==========================================
    // MODE 2: Network binding
    // ==========================================
    if (mode === 'network-binding') {
      const currentPrefix = SessionManager.extractIpPrefix(clientIp);
      const baselinePrefix = baseline?.ipPrefix || SessionManager.extractIpPrefix(baseline?.ip || '');

      if (currentPrefix !== baselinePrefix) {
        const detectionLatencyMs = Date.now() - startTime;
        res.setHeader('X-Session-Guard-Decision', 'Reject');
        res.setHeader('X-Session-Guard-Mode', 'network-binding');
        return res.status(403).json({
          error: 'Access rejected: network mismatch with session baseline.',
          code: 'NETWORK_BINDING_REJECT',
          decision: 'Reject',
          mode: 'network-binding',
          detectionLatencyMs,
          timeToContainmentMs: null // unbounded/not supported in network-binding
        });
      }

      res.setHeader('X-Session-Guard-Decision', 'Allow');
      res.setHeader('X-Session-Guard-Mode', 'network-binding');
      return next();
    }

    // ==========================================
    // MODE 3: Network + User-Agent
    // ==========================================
    if (mode === 'network-ua') {
      const currentPrefix = SessionManager.extractIpPrefix(clientIp);
      const baselinePrefix = baseline?.ipPrefix || SessionManager.extractIpPrefix(baseline?.ip || '');
      const baselineUa = baseline?.userAgent || '';

      const netMismatch = currentPrefix !== baselinePrefix;
      const uaMismatch = userAgent !== baselineUa;

      if (netMismatch || uaMismatch) {
        const detectionLatencyMs = Date.now() - startTime;
        res.setHeader('X-Session-Guard-Decision', 'Reject');
        res.setHeader('X-Session-Guard-Mode', 'network-ua');
        return res.status(403).json({
          error: 'Access rejected: network or user-agent mismatch with session baseline.',
          code: 'NETWORK_UA_REJECT',
          decision: 'Reject',
          mode: 'network-ua',
          reasons: { netMismatch, uaMismatch },
          detectionLatencyMs,
          timeToContainmentMs: null // unbounded/not supported in network-ua
        });
      }

      res.setHeader('X-Session-Guard-Decision', 'Allow');
      res.setHeader('X-Session-Guard-Mode', 'network-ua');
      return next();
    }

    // ==========================================
    // MODE 4: SessionGuard (Multi-Signal Engine)
    // ==========================================
    const now = Date.now();

    // Signal extraction
    const fN = extractNetworkSignal(clientIp, baseline);
    const fD = extractDeviceSignal(req.headers, baseline);
    const fT = extractTemporalSignal(now, baseline);
    const fQ = extractSequenceSignal(currentPath, currentMethod, baseline);
    const fC = extractConcurrencySignal(clientIp, req.headers, now, baseline, config.thresholds.concurrencyWindowSec);
    const fA = extractSensitiveSignal(currentPath, currentMethod);

    const signals = { fN, fD, fT, fQ, fC, fA };

    // Dynamic configurable weights
    const w = config.weights;
    const Rt = (
      w.wN * fN +
      w.wD * fD +
      w.wT * fT +
      w.wQ * fQ +
      w.wC * fC +
      w.wA * fA
    );

    const { tau1, tau2, singleSignalFloor } = config.thresholds;

    // Hard Rule 2: Concurrency conflict (f_C >= 0.5) co-occurring with sensitive action (f_A = 1.0)
    // hard-escalates directly to Terminate+Notify regardless of R_t
    if (fC >= 0.5 && fA === 1.0) {
      return executeTerminateAndNotify({
        req,
        res,
        account,
        sessionId,
        mode: 'session-guard',
        riskScore: Math.max(Rt, 0.95),
        signals,
        reason: 'Hard escalation: Concurrent token conflict during sensitive action attempt.',
        startTime
      });
    }

    // Tier Decision Logic
    let decision = 'Allow';

    if (Rt >= tau2) {
      // Hard Rule 1: No single signal may alone push past tau2.
      // Require >= 2 signals above singleSignalFloor before allowing escalation to Terminate+Notify.
      const elevatedSignalsCount = [fN, fD, fT, fQ, fC, fA].filter(val => val >= singleSignalFloor).length;
      if (elevatedSignalsCount >= 2) {
        decision = 'Terminate+Notify';
      } else {
        // Clamp to Step-Up
        decision = 'Step-Up';
      }
    } else if (Rt >= tau1) {
      decision = 'Step-Up';
    } else {
      decision = 'Allow';
    }

    res.setHeader('X-Session-Guard-Decision', decision);
    res.setHeader('X-Session-Guard-Score', Rt.toFixed(4));
    res.setHeader('X-Session-Guard-Mode', 'session-guard');

    // Record incoming context into sliding window so subsequent interleaved requests detect conflict
    if (baseline && decision !== 'Terminate+Notify') {
      updateContextHistory(baseline, clientIp, req.headers, now, config.thresholds.concurrencyWindowSec);
      await SessionManager.saveBaseline(sessionId, baseline);
    }

    if (decision === 'Terminate+Notify') {
      return executeTerminateAndNotify({
        req,
        res,
        account,
        sessionId,
        mode: 'session-guard',
        riskScore: Rt,
        signals,
        reason: `Risk score ${Rt.toFixed(3)} breached threshold tau2 (${tau2}) with multiple corroborating signals.`,
        startTime
      });
    }

    if (decision === 'Step-Up') {
      return executeStepUpChallenge({
        req,
        res,
        account,
        sessionId,
        mode: 'session-guard',
        riskScore: Rt,
        signals,
        reason: `Risk score ${Rt.toFixed(3)} reached Step-Up verification tier (>= ${tau1}).`,
        startTime
      });
    }

    // Decision === 'Allow'
    // Update baseline states: timing, sequence, context
    if (baseline) {
      updateTimingState(baseline, now);
      updateSequenceHistory(baseline, currentPath, currentMethod, now);
      updateContextHistory(baseline, clientIp, req.headers, now, config.thresholds.concurrencyWindowSec);
      await SessionManager.saveBaseline(sessionId, baseline);
    }

    next();
  };
}

module.exports = sessionGuardMiddleware;
