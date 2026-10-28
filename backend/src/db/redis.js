const Redis = require('ioredis');
const RedisMock = require('ioredis-mock');

let redisClient = null;
let isInMemory = false;

async function initRedis(redisUrl) {
  if (redisUrl) {
    try {
      const client = new Redis(redisUrl, {
        maxRetriesPerRequest: 1,
        connectTimeout: 1500,
        retryStrategy: () => null // don't loop retry if offline
      });

      await new Promise((resolve, reject) => {
        client.once('ready', resolve);
        client.once('error', reject);
      });

      console.log('Connected to external Redis server.');
      redisClient = client;
      isInMemory = false;
      return redisClient;
    } catch (err) {
      console.warn('Could not connect to external Redis, falling back to ioredis-mock:', err.message);
    }
  }

  console.log('Initializing in-memory Redis instance via ioredis-mock...');
  redisClient = new RedisMock();
  isInMemory = true;
  console.log('Redis initialized successfully.');
  return redisClient;
}

function getRedis() {
  if (!redisClient) {
    throw new Error('Redis client not initialized. Call initRedis() first.');
  }
  return redisClient;
}

module.exports = {
  initRedis,
  getRedis,
  isInMemory: () => isInMemory
};

