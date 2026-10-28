const path = require('path');

const config = {
  port: parseInt(process.env.PORT || '5000', 10),
  host: process.env.HOST || '127.0.0.1',
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Database configuration
  databaseUrl: process.env.DATABASE_URL || null,
  redisUrl: process.env.REDIS_URL || null,
  
  // Session parameters
  session: {
    cookieName: 'sg_session_id',
    idleTimeoutMs: 15 * 60 * 1000,        // 15 minutes idle timeout
    absoluteTimeoutMs: 24 * 60 * 60 * 1000, // 24 hours absolute timeout
    cookieSecure: process.env.COOKIE_SECURE === 'true', // false for localhost dev
    cookieSameSite: 'lax',
    salt: process.env.SESSION_SALT || 'sg_session_secret_salt_2026'
  },
  
  // SessionGuard weights (configurable, loaded at runtime)
  weights: {
    wC: parseFloat(process.env.SG_WEIGHT_C || '0.30'), // Concurrency
    wA: parseFloat(process.env.SG_WEIGHT_A || '0.20'), // Sensitive action
    wD: parseFloat(process.env.SG_WEIGHT_D || '0.20'), // Device / Header consistency
    wQ: parseFloat(process.env.SG_WEIGHT_Q || '0.15'), // Request sequence plausibility
    wT: parseFloat(process.env.SG_WEIGHT_T || '0.10'), // Temporal rhythm
    wN: parseFloat(process.env.SG_WEIGHT_N || '0.05')  // Network consistency
  },
  
  // Decision thresholds
  thresholds: {
    tau1: parseFloat(process.env.SG_TAU_1 || '0.35'), // Allow if < tau1, Step-Up if >= tau1
    tau2: parseFloat(process.env.SG_TAU_2 || '0.65'), // Terminate+Notify if >= tau2
    singleSignalFloor: 0.40, // Floor required for >=2 signals to breach tau2
    concurrencyWindowSec: 5  // Window Delta for concurrency detection (seconds)
  },
  
  // Default middleware mode: 'session-guard', 'network-ua', 'network-binding', 'token-only'
  defaultMode: process.env.SG_MODE || 'session-guard',
  
  // Mail sink configuration
  mailSink: {
    port: parseInt(process.env.MAIL_SINK_PORT || '5025', 10),
    url: process.env.MAIL_SINK_URL || 'http://127.0.0.1:5025/api/mail'
  }
};

module.exports = config;

