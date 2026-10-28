const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const config = require('./config');
const { initPostgres } = require('./db/postgres');
const { initRedis } = require('./db/redis');
const { startMailSinkServer, stopMailSinkServer } = require('./services/mailSink');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const sensitiveRoutes = require('./routes/sensitive');
const notificationRoutes = require('./routes/notifications');
const debugRoutes = require('./routes/debug');

async function createApp() {
  const app = express();

  // Middleware
  app.use(cors({
    origin: (origin, callback) => callback(null, true), // allow all origins for dev/harness
    credentials: true
  }));
  app.use(cookieParser());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Request logger for debugging if enabled
  if (process.env.DEBUG_REQUESTS === 'true') {
    app.use((req, res, next) => {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} Mode=${req.headers['x-session-guard-mode'] || 'default'}`);
      next();
    });
  }

  // Health check
  app.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      service: 'sessionguard-backend',
      timestamp: Date.now()
    });
  });

  // Mount API routers
  app.use('/api/auth', authRoutes);
  app.use('/api/user', userRoutes);
  app.use('/api/sensitive', sensitiveRoutes);
  app.use('/api/notifications', notificationRoutes);
  app.use('/api/debug', debugRoutes);

  // Serve static frontend build if present
  const frontendDist = path.join(__dirname, '../../frontend/dist');
  app.use(express.static(frontendDist));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) {
      return next();
    }
    const indexPath = path.join(frontendDist, 'index.html');
    res.sendFile(indexPath, (err) => {
      if (err) {
        res.status(200).send(`
          <h2>SessionGuard Backend Active</h2>
          <p>API endpoints ready at /api/...</p>
        `);
      }
    });
  });

  return app;
}

let serverInstance = null;

async function startServer(port = config.port) {
  // 1. Initialize databases
  await initPostgres(config.databaseUrl);
  await initRedis(config.redisUrl);

  // 2. Start mock mail sink
  await startMailSinkServer(config.mailSink.port);

  // 3. Start Express server
  const app = await createApp();
  return new Promise((resolve, reject) => {
    serverInstance = app.listen(port, '0.0.0.0', () => {
      console.log(`====================================================`);
      console.log(` SessionGuard Server running on http://127.0.0.1:${port}`);
      console.log(` Mock Mail Sink running on http://127.0.0.1:${config.mailSink.port}`);
      console.log(` Mode: ${config.defaultMode}`);
      console.log(`====================================================`);
      resolve(serverInstance);
    });

    serverInstance.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`Port ${port} is in use.`);
      }
      reject(err);
    });
  });
}

function stopServer() {
  stopMailSinkServer();
  if (serverInstance) {
    serverInstance.close();
    serverInstance = null;
  }
}

if (require.main === module) {
  startServer().catch(err => {
    console.error('Failed to start SessionGuard server:', err);
    process.exit(1);
  });
}

module.exports = {
  createApp,
  startServer,
  stopServer
};

