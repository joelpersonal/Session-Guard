const axios = require('axios');

const BASE_URL = process.env.API_BASE_URL || 'http://127.0.0.1:5000';

function generateAccounts(count = 60) {
  const accounts = [];
  for (let i = 0; i < count; i++) {
    accounts.push({
      id: `acc_synth_${i.toString().padStart(3, '0')}`,
      email: `synth_user_${i.toString().padStart(3, '0')}@sessionguard-test.local`,
      password: `TestP@ssword_${i}!`,
      name: `Synthetic User ${i}`,
      recoveryEmail: `synth_recovery_${i.toString().padStart(3, '0')}@sessionguard-test.local`
    });
  }
  return accounts;
}

async function seedAccounts(accounts, baseUrl = BASE_URL) {
  const res = await axios.post(`${baseUrl}/api/debug/seed`, { accounts });
  return res.data;
}

module.exports = {
  generateAccounts,
  seedAccounts,
  BASE_URL
};

