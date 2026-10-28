const express = require('express');
const router = express.Router();
const { getPool } = require('../db/postgres');

// GET /api/notifications/feedback
// Records owner's response as a label on the audit record
router.get('/feedback', async (req, res) => {
  try {
    const { token, action } = req.query;
    if (!token || !action) {
      return res.status(400).send('<h3>Invalid request: token and action are required.</h3>');
    }

    const pool = getPool();

    // Find notification by action token
    const notifResult = await pool.query(
      'SELECT * FROM notifications WHERE action_token = $1',
      [token]
    );

    if (notifResult.rows.length === 0) {
      return res.status(404).send('<h3>Security notification not found or token expired.</h3>');
    }

    const notification = notifResult.rows[0];
    const now = new Date();

    // Update notification
    await pool.query(
      'UPDATE notifications SET feedback = $1 WHERE id = $2',
      [action, notification.id]
    );

    // Update audit record with owner feedback label (used for reporting)
    if (notification.audit_log_id) {
      await pool.query(`
        UPDATE audit_logs 
        SET owner_feedback = $1, feedback_at = $2 
        WHERE id = $3
      `, [action, now, notification.audit_log_id]);
    }

    const feedbackDisplay = action === 'confirmed_me' 
      ? 'Legitimate Activity Confirmed ("This was me")'
      : 'Session Hijack Confirmed ("This was NOT me")';

    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Security Feedback Recorded</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
          .card { background: #1e293b; padding: 32px; border-radius: 12px; border: 1px solid #334155; max-width: 500px; text-align: center; box-shadow: 0 10px 25px rgba(0,0,0,0.3); }
          h2 { color: #38bdf8; margin-top: 0; }
          .badge { display: inline-block; padding: 6px 12px; border-radius: 999px; background: ${action === 'confirmed_me' ? '#065f46' : '#991b1b'}; color: white; font-weight: bold; margin: 12px 0; }
          p { color: #94a3b8; font-size: 15px; line-height: 1.6; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Security Feedback Recorded</h2>
          <div class="badge">${feedbackDisplay}</div>
          <p>Thank you for verifying your activity. Your response has been recorded into the security audit log for analysis.</p>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send(`<h3>Error processing feedback: ${err.message}</h3>`);
  }
});

// POST /api/notifications/feedback (JSON variant for programmatic calls)
router.post('/feedback', async (req, res) => {
  try {
    const { token, action } = req.body;
    if (!token || !action) {
      return res.status(400).json({ error: 'Missing token or action.' });
    }

    const pool = getPool();
    const notifResult = await pool.query(
      'SELECT * FROM notifications WHERE action_token = $1',
      [token]
    );

    if (notifResult.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found.' });
    }

    const notification = notifResult.rows[0];
    const now = new Date();

    await pool.query('UPDATE notifications SET feedback = $1 WHERE id = $2', [action, notification.id]);
    if (notification.audit_log_id) {
      await pool.query('UPDATE audit_logs SET owner_feedback = $1, feedback_at = $2 WHERE id = $3', [action, now, notification.audit_log_id]);
    }

    res.json({ success: true, notificationId: notification.id, feedback: action });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/notifications/list
router.get('/list', async (req, res) => {
  try {
    const pool = getPool();
    const result = await pool.query('SELECT * FROM notifications ORDER BY dispatched_at DESC LIMIT 50');
    res.json({ notifications: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;

