const http = require('http');
const crypto = require('crypto');
const config = require('../config');
const { getPool } = require('../db/postgres');

/**
 * Dispatch an out-of-band notification to the mock mail sink.
 * Measures real round-trip network dispatch latency.
 */
async function dispatchSecurityAlert({ account, sessionId, auditLogId, reason, riskScore, signals, clientIp, userAgent }) {
  const dispatchStartTime = Date.now();
  const notificationId = `notif_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  const actionToken = crypto.randomBytes(32).toString('hex');
  
  const baseUrl = `http://${config.host}:${config.port}`;
  const confirmMeUrl = `${baseUrl}/api/notifications/feedback?token=${actionToken}&action=confirmed_me`;
  const reportHijackUrl = `${baseUrl}/api/notifications/feedback?token=${actionToken}&action=reported_hijack`;

  const subject = `[SECURITY ALERT] Suspicious activity detected on your account`;
  const body = `
Security Alert:
We detected suspicious activity on your account (${account.email}).
Risk Score: ${riskScore.toFixed(3)}
Reason: ${reason}
IP Address: ${clientIp}
User-Agent: ${userAgent}
Time: ${new Date(dispatchStartTime).toISOString()}

If this was you:
${confirmMeUrl}

If this was NOT you (Report Hijack):
${reportHijackUrl}

All active sessions have been terminated to safeguard your account.
  `.trim();

  const payload = JSON.stringify({
    id: notificationId,
    incidentId: auditLogId,
    to: account.email,
    subject,
    body,
    actionToken,
    dispatchedAt: new Date(dispatchStartTime).toISOString()
  });

  const mailSinkUrl = new URL(config.mailSink.url);

  // Send real HTTP request to mail sink
  let dispatchLatencyMs = 0;
  let status = 'failed';

  try {
    const response = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: mailSinkUrl.hostname,
        port: mailSinkUrl.port,
        path: mailSinkUrl.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        },
        timeout: 2000
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(data || '{}'));
          } else {
            reject(new Error(`Mail sink error HTTP ${res.statusCode}: ${data}`));
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Mail sink request timeout'));
      });

      req.write(payload);
      req.end();
    });

    const dispatchEndTime = Date.now();
    dispatchLatencyMs = dispatchEndTime - dispatchStartTime;
    status = 'delivered';
  } catch (err) {
    console.warn(`Mail sink dispatch failed (${err.message}). Recording local fallback.`);
    const dispatchEndTime = Date.now();
    dispatchLatencyMs = dispatchEndTime - dispatchStartTime;
    status = 'failed';
  }

  // Persist notification record in PostgreSQL
  try {
    const pool = getPool();
    await pool.query(`
      INSERT INTO notifications (id, account_id, audit_log_id, title, message, action_token, status, dispatched_at, delivered_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, [
      notificationId,
      account.id,
      auditLogId,
      subject,
      body,
      actionToken,
      status,
      new Date(dispatchStartTime),
      new Date(dispatchStartTime + dispatchLatencyMs)
    ]);
  } catch (dbErr) {
    console.error('Failed to store notification record in Postgres:', dbErr.message);
  }

  return {
    notificationId,
    actionToken,
    status,
    dispatchLatencyMs
  };
}

module.exports = {
  dispatchSecurityAlert
};

