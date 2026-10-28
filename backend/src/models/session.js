const crypto = require('crypto');
const config = require('../config');
const { getRedis } = require('../db/redis');

class SessionManager {
  /**
   * Generate high-entropy 256-bit cryptographically secure session ID
   */
  static generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Truncate IP into network prefix (/24 for IPv4, /48 for IPv6)
   */
  static extractIpPrefix(ip) {
    if (!ip) return '0.0.0.0/0';
    // Remove IPv6-mapped IPv4 prefix if present
    const cleanIp = ip.replace(/^::ffff:/, '');
    if (cleanIp.includes('.')) {
      const parts = cleanIp.split('.');
      return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
    if (cleanIp.includes(':')) {
      const parts = cleanIp.split(':');
      return `${parts.slice(0, 3).join(':')}::/48`;
    }
    return cleanIp;
  }

  /**
   * Generate salted hash of client headers
   */
  static hashClientHeaders(headers, salt = config.session.salt) {
    const ua = headers['user-agent'] || '';
    const lang = headers['accept-language'] || '';
    const enc = headers['accept-encoding'] || '';
    const secChUa = headers['sec-ch-ua'] || '';
    const secPlatform = headers['sec-ch-ua-platform'] || '';

    const payload = `${ua}|${lang}|${enc}|${secChUa}|${secPlatform}|${salt}`;
    return crypto.createHash('sha256').update(payload).digest('hex');
  }

  /**
   * Create a new session in Redis and register baseline record B_s
   */
  static async createSession({ accountId, clientIp, headers, previousSessionId = null }) {
    const redis = getRedis();

    // Session rotation on login: if previous session provided, destroy it first
    if (previousSessionId) {
      await this.destroySession(previousSessionId);
    }

    const sessionId = this.generateSessionId();
    const now = Date.now();
    const ipPrefix = this.extractIpPrefix(clientIp);
    const headerHash = this.hashClientHeaders(headers);

    const sessionData = {
      sessionId,
      accountId,
      createdAt: now,
      lastActivityAt: now,
      idleTimeoutMs: config.session.idleTimeoutMs,
      absoluteTimeoutMs: config.session.absoluteTimeoutMs,
      isRevoked: false
    };

    // Baseline record B_s
    const baseline = {
      ip: clientIp,
      ipPrefix,
      userAgent: headers['user-agent'] || '',
      headerHash,
      createdAt: now,
      lastRequestAt: now,
      timing: {
        intervals: [],
        meanInterval: 0,
        varianceInterval: 0
      },
      requestHistory: [], // bounded to last 20 requests
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

    const ttlSec = Math.ceil(config.session.absoluteTimeoutMs / 1000);

    // Save session state and baseline in Redis
    await redis.set(`session:${sessionId}`, JSON.stringify(sessionData), 'EX', ttlSec);
    await redis.set(`session_baseline:${sessionId}`, JSON.stringify(baseline), 'EX', ttlSec);

    // Add session to account active sessions set
    await redis.sadd(`user_sessions:${accountId}`, sessionId);

    return { sessionId, sessionData, baseline };
  }

  /**
   * Retrieve session by sessionId, validating idle and absolute expiration
   */
  static async getSession(sessionId) {
    if (!sessionId) return null;
    const redis = getRedis();

    const raw = await redis.get(`session:${sessionId}`);
    if (!raw) return null;

    let session;
    try {
      session = JSON.parse(raw);
    } catch {
      return null;
    }

    if (session.isRevoked) {
      await this.destroySession(sessionId);
      return null;
    }

    const now = Date.now();

    // Check absolute expiration
    if (now - session.createdAt > session.absoluteTimeoutMs) {
      await this.destroySession(sessionId);
      return null;
    }

    // Check idle expiration
    if (now - session.lastActivityAt > session.idleTimeoutMs) {
      await this.destroySession(sessionId);
      return null;
    }

    // Update last activity
    session.lastActivityAt = now;
    const remainingTtlSec = Math.max(1, Math.ceil((session.createdAt + session.absoluteTimeoutMs - now) / 1000));
    await redis.set(`session:${sessionId}`, JSON.stringify(session), 'EX', remainingTtlSec);

    return session;
  }

  /**
   * Get baseline record B_s
   */
  static async getBaseline(sessionId) {
    const redis = getRedis();
    const raw = await redis.get(`session_baseline:${sessionId}`);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  /**
   * Save updated baseline record B_s
   */
  static async saveBaseline(sessionId, baseline) {
    const redis = getRedis();
    const ttlSec = Math.ceil(config.session.absoluteTimeoutMs / 1000);
    await redis.set(`session_baseline:${sessionId}`, JSON.stringify(baseline), 'EX', ttlSec);
  }

  /**
   * Destroy individual session
   */
  static async destroySession(sessionId) {
    if (!sessionId) return;
    const redis = getRedis();

    const raw = await redis.get(`session:${sessionId}`);
    if (raw) {
      try {
        const session = JSON.parse(raw);
        if (session.accountId) {
          await redis.srem(`user_sessions:${session.accountId}`, sessionId);
        }
      } catch {}
    }

    await redis.del(`session:${sessionId}`);
    await redis.del(`session_baseline:${sessionId}`);
  }

  /**
   * Revoke EVERY session bound to the account (atomic containment action #1)
   */
  static async revokeAllUserSessions(accountId) {
    if (!accountId) return 0;
    const redis = getRedis();

    const sessionIds = await redis.smembers(`user_sessions:${accountId}`);
    if (!sessionIds || sessionIds.length === 0) return 0;

    const pipeline = redis.pipeline ? redis.pipeline() : null;
    for (const sid of sessionIds) {
      if (pipeline) {
        pipeline.del(`session:${sid}`);
        pipeline.del(`session_baseline:${sid}`);
      } else {
        await redis.del(`session:${sid}`);
        await redis.del(`session_baseline:${sid}`);
      }
    }

    if (pipeline) {
      pipeline.del(`user_sessions:${accountId}`);
      await pipeline.exec();
    } else {
      await redis.del(`user_sessions:${accountId}`);
    }

    return sessionIds.length;
  }

  /**
   * Invalidate refresh token family for account (atomic containment action #2)
   */
  static async invalidateTokenFamily(accountId) {
    if (!accountId) return;
    const redis = getRedis();
    await redis.del(`account_refresh:${accountId}`);

    // Update in Postgres as well
    try {
      const { getPool } = require('../db/postgres');
      const pool = getPool();
      await pool.query(
        'UPDATE refresh_tokens SET is_revoked = TRUE WHERE account_id = $1',
        [accountId]
      );
    } catch (err) {
      console.warn('Could not revoke refresh tokens in Postgres:', err.message);
    }
  }
}

module.exports = SessionManager;

