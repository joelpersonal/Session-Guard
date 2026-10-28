const { Pool: PgPool } = require('pg');
const { newDb } = require('pg-mem');

let pool = null;
let isInMemory = false;

async function initPostgres(databaseUrl) {
  if (databaseUrl) {
    try {
      const realPool = new PgPool({ connectionString: databaseUrl });
      // Test connection
      await realPool.query('SELECT 1');
      console.log('Connected to real PostgreSQL database.');
      pool = realPool;
      isInMemory = false;
      await createSchema(pool);
      return pool;
    } catch (err) {
      console.warn('Could not connect to external PostgreSQL, falling back to pg-mem:', err.message);
    }
  }

  // In-memory PostgreSQL via pg-mem
  console.log('Initializing in-memory PostgreSQL instance via pg-mem...');
  const memDb = newDb();
  
  // Register custom or standard functions if needed
  memDb.public.registerFunction({
    name: 'gen_random_uuid',
    implementation: () => require('crypto').randomUUID()
  });

  const { Pool: MemPool } = memDb.adapters.createPg();
  pool = new MemPool();
  isInMemory = true;
  await createSchema(pool);
  console.log('PostgreSQL schema initialized successfully.');
  return pool;
}

async function createSchema(p) {
  await p.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id VARCHAR(64) PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      name VARCHAR(255),
      recovery_email VARCHAR(255),
      mfa_enabled BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id VARCHAR(64) PRIMARY KEY,
      account_id VARCHAR(64),
      session_id VARCHAR(128),
      mode VARCHAR(32),
      risk_score DOUBLE PRECISION,
      signals TEXT,
      decision VARCHAR(32),
      reason TEXT,
      client_ip VARCHAR(64),
      user_agent TEXT,
      request_path VARCHAR(255),
      request_method VARCHAR(16),
      notification_status VARCHAR(32),
      notification_id VARCHAR(64),
      notification_latency_ms DOUBLE PRECISION,
      time_to_containment_ms DOUBLE PRECISION,
      detection_latency_ms DOUBLE PRECISION,
      owner_feedback VARCHAR(32),
      feedback_at TIMESTAMP WITH TIME ZONE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id VARCHAR(64) PRIMARY KEY,
      account_id VARCHAR(64),
      audit_log_id VARCHAR(64),
      title VARCHAR(255),
      message TEXT,
      action_token VARCHAR(128),
      status VARCHAR(32),
      dispatched_at TIMESTAMP WITH TIME ZONE,
      delivered_at TIMESTAMP WITH TIME ZONE,
      feedback VARCHAR(32)
    );
  `);

  await p.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id VARCHAR(64) PRIMARY KEY,
      account_id VARCHAR(64),
      family_id VARCHAR(64),
      token_hash VARCHAR(255),
      is_revoked BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP WITH TIME ZONE
    );
  `);
}

function getPool() {
  if (!pool) {
    throw new Error('PostgreSQL pool not initialized. Call initPostgres() first.');
  }
  return pool;
}

module.exports = {
  initPostgres,
  getPool,
  isInMemory: () => isInMemory
};

