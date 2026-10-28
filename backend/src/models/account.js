const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { getPool } = require('../db/postgres');

class Account {
  static async create({ email, password, name = '', recoveryEmail = '' }) {
    const pool = getPool();
    const id = `acc_${crypto.randomBytes(12).toString('hex')}`;
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const result = await pool.query(`
      INSERT INTO accounts (id, email, password_hash, name, recovery_email)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, email, name, recovery_email, mfa_enabled, created_at
    `, [id, email.toLowerCase(), passwordHash, name, recoveryEmail]);

    return result.rows[0];
  }

  static async findByEmail(email) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT * FROM accounts WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    return result.rows[0] || null;
  }

  static async findById(id) {
    const pool = getPool();
    const result = await pool.query(
      'SELECT id, email, name, recovery_email, mfa_enabled, created_at FROM accounts WHERE id = $1',
      [id]
    );
    return result.rows[0] || null;
  }

  static async verifyPassword(candidatePassword, passwordHash) {
    return bcrypt.compare(candidatePassword, passwordHash);
  }

  static async updatePassword(id, newPassword) {
    const pool = getPool();
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(newPassword, salt);
    await pool.query('UPDATE accounts SET password_hash = $1 WHERE id = $2', [passwordHash, id]);
    return true;
  }

  static async updateMfa(id, enabled) {
    const pool = getPool();
    await pool.query('UPDATE accounts SET mfa_enabled = $1 WHERE id = $2', [enabled, id]);
    return true;
  }

  static async updateRecoveryEmail(id, recoveryEmail) {
    const pool = getPool();
    await pool.query('UPDATE accounts SET recovery_email = $1 WHERE id = $2', [recoveryEmail, id]);
    return true;
  }
}

module.exports = Account;

