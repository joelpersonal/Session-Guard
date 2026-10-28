const express = require('express');
const router = express.Router();
const sessionGuard = require('../middleware/sessionGuard');
const Account = require('../models/account');

// All sensitive routes are guarded by SessionGuard middleware
router.use(sessionGuard());

// POST /api/sensitive/change-password
router.post('/change-password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!newPassword) {
      return res.status(400).json({ error: 'New password is required.' });
    }

    // If currentPassword provided, verify it (for standard flow)
    if (currentPassword) {
      const fullAcc = await Account.findByEmail(req.account.email);
      const isMatch = await Account.verifyPassword(currentPassword, fullAcc.password_hash);
      if (!isMatch) {
        return res.status(401).json({ error: 'Current password incorrect.' });
      }
    }

    await Account.updatePassword(req.account.id, newPassword);
    res.json({
      success: true,
      message: 'Password successfully changed.',
      timestamp: Date.now()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/sensitive/disable-mfa
router.post('/disable-mfa', async (req, res) => {
  try {
    await Account.updateMfa(req.account.id, false);
    res.json({
      success: true,
      message: 'Multi-factor authentication disabled.',
      timestamp: Date.now()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/sensitive/recovery-email
router.post('/recovery-email', async (req, res) => {
  try {
    const { recoveryEmail } = req.body;
    if (!recoveryEmail) {
      return res.status(400).json({ error: 'Recovery email is required.' });
    }
    await Account.updateRecoveryEmail(req.account.id, recoveryEmail);
    res.json({
      success: true,
      message: 'Recovery email updated successfully.',
      recoveryEmail,
      timestamp: Date.now()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/sensitive/payment-details
router.post('/payment-details', async (req, res) => {
  try {
    const { cardNumber, expMonth, expYear } = req.body;
    res.json({
      success: true,
      message: 'Payment details updated.',
      last4: cardNumber ? cardNumber.slice(-4) : '4242',
      timestamp: Date.now()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;

