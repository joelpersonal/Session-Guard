const crypto = require('crypto');
const SessionManager = require('../models/session');
const { getPool } = require('../db/postgres');
const { dispatchSecurityAlert } = require('../services/notification');
const Account = require('../models/account');

/**
 * Execute atomic containment and notification on Terminate+Notify
 */
async function executeTerminateAndNotify({
  req,
  res,
  account,
  sessionId,
  mode,
  riskScore,
  signals,
  reason,
  startTime
}) {
  const auditLogId = `audit_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  const decisionTime = Date.now();
  const detectionLatencyMs = decisionTime - startTime;

  const clientIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'unknown';

  // 1. Revoke every session in Redis bound to the account
  const revocationStart = Date.now();
  const revokedCount = await SessionManager.revokeAllUserSessions(account.id);

  // 2. Invalidate refresh/token family for that account
  await SessionManager.invalidateTokenFamily(account.id);
  const timeToContainmentMs = Date.now() - startTime;

  // 3. Dispatch out-of-band notification (to mock mail sink)
  const notifResult = await dispatchSecurityAlert({
    account,
    sessionId,
    auditLogId,
    reason,
    riskScore,
    signals,
    clientIp,
    userAgent
  });

  // 4. Write audit record to PostgreSQL
  try {
    const pool = getPool();
    await pool.query(`
      INSERT INTO audit_logs (
        id, account_id, session_id, mode, risk_score, signals, decision, reason,
        client_ip, user_agent, request_path, request_method, notification_status,
        notification_id, notification_latency_ms, time_to_containment_ms, detection_latency_ms
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
    `, [
      auditLogId,
      account.id,
      sessionId,
      mode,
      riskScore,
      JSON.stringify(signals),
      'Terminate+Notify',
      reason,
      clientIp,
      userAgent,
      req.originalUrl || req.path,
      req.method,
      notifResult.status,
      notifResult.notificationId,
      notifResult.dispatchLatencyMs,
      timeToContainmentMs,
      detectionLatencyMs
    ]);
  } catch (err) {
    console.error('Failed to write audit log in Postgres:', err.message);
  }

  // Clear cookie
  res.clearCookie('sg_session_id', { path: '/' });

  return res.status(403).json({
    error: 'Session terminated due to security violation',
    code: 'SESSION_TERMINATED',
    auditLogId,
    decision: 'Terminate+Notify',
    reason,
    riskScore,
    signals,
    detectionLatencyMs,
    timeToContainmentMs,
    notificationLatencyMs: notifResult.dispatchLatencyMs,
    revokedSessions: revokedCount
  });
}

/**
 * Handle Step-Up challenge issuance
 */
async function executeStepUpChallenge({
  req,
  res,
  account,
  sessionId,
  mode,
  riskScore,
  signals,
  reason,
  startTime
}) {
  const challengeToken = crypto.randomBytes(24).toString('hex');
  const detectionLatencyMs = Date.now() - startTime;
  const { getRedis } = require('../db/redis');
  const redis = getRedis();

  // Store challenge token in Redis with 5 min expiration
  await redis.set(`step_up_challenge:${sessionId}`, JSON.stringify({
    token: challengeToken,
    accountId: account.id,
    riskScore,
    signals,
    createdAt: Date.now()
  }), 'EX', 300);

  // Log Step-Up decision in audit log
  try {
    const pool = getPool();
    const auditLogId = `audit_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
    const clientIp = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'unknown';

    await pool.query(`
      INSERT INTO audit_logs (
        id, account_id, session_id, mode, risk_score, signals, decision, reason,
        client_ip, user_agent, request_path, request_method, notification_status,
        detection_latency_ms
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
    `, [
      auditLogId,
      account.id,
      sessionId,
      mode,
      riskScore,
      JSON.stringify(signals),
      'Step-Up',
      reason,
      clientIp,
      userAgent,
      req.originalUrl || req.path,
      req.method,
      'none',
      detectionLatencyMs
    ]);
  } catch (err) {
    console.error('Failed to log step-up challenge:', err.message);
  }

  return res.status(428).json({
    error: 'Additional verification required',
    code: 'STEP_UP_REQUIRED',
    challengeToken,
    decision: 'Step-Up',
    reason,
    riskScore,
    signals,
    detectionLatencyMs
  });
}

module.exports = {
  executeTerminateAndNotify,
  executeStepUpChallenge
};

