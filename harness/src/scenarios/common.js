const axios = require('axios');

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const UA_DESKTOP_CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
const UA_MOBILE_SAFARI = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1';
const UA_ATTACKER_PYTHON = 'Python-urllib/3.10';
const UA_ATTACKER_CURL = 'curl/8.4.0';

const IP_PRIMARY = '198.51.100.15';
const IP_MOBILE_SWITCH = '203.0.113.88';
const IP_ATTACKER_FOREIGN = '185.220.101.5';
const IP_ATTACKER_SAME_SUBNET = '198.51.100.22';

async function loginUser(baseUrl, account, ip = IP_PRIMARY, ua = UA_DESKTOP_CHROME) {
  const start = Date.now();
  const res = await axios.post(`${baseUrl}/api/auth/login`, {
    email: account.email,
    password: account.password
  }, {
    headers: {
      'User-Agent': ua,
      'X-Test-Ip': ip,
      'Accept-Language': 'en-US,en;q=0.9',
      'Sec-Ch-Ua-Platform': ua.includes('iPhone') ? 'iOS' : 'Windows'
    },
    validateStatus: () => true
  });

  return {
    status: res.status,
    sessionId: res.data.sessionId,
    account: res.data.account,
    loginTimeMs: Date.now() - start
  };
}

async function sendGuardedRequest(baseUrl, method, path, {
  sessionId,
  ip = IP_PRIMARY,
  ua = UA_DESKTOP_CHROME,
  body = null,
  mode = 'session-guard',
  extraHeaders = {}
}) {
  const startTime = Date.now();
  const headers = {
    'User-Agent': ua,
    'X-Test-Ip': ip,
    'X-Session-Guard-Mode': mode,
    'X-Session-Id': sessionId,
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Ch-Ua-Platform': ua.includes('iPhone') ? 'iOS' : 'Windows',
    ...extraHeaders
  };

  const res = await axios({
    method,
    url: `${baseUrl}${path}`,
    headers,
    data: body,
    validateStatus: () => true
  });

  const durationMs = Date.now() - startTime;
  const decisionHeader = res.headers['x-session-guard-decision'];
  const scoreHeader = res.headers['x-session-guard-score'];

  let decision = decisionHeader || 'Allow';
  if (!decisionHeader) {
    if (res.status === 403 || res.status === 401) {
      decision = 'Reject';
    } else if (res.status === 428) {
      decision = 'Step-Up';
    } else {
      decision = 'Allow';
    }
  }

  return {
    status: res.status,
    decision,
    score: scoreHeader ? parseFloat(scoreHeader) : (res.data?.riskScore || 0.0),
    data: res.data,
    durationMs,
    detectionLatencyMs: res.data?.detectionLatencyMs || durationMs,
    timeToContainmentMs: res.data?.timeToContainmentMs || null,
    notificationLatencyMs: res.data?.notificationLatencyMs || null
  };
}

module.exports = {
  sleep,
  loginUser,
  sendGuardedRequest,
  UA_DESKTOP_CHROME,
  UA_MOBILE_SAFARI,
  UA_ATTACKER_PYTHON,
  UA_ATTACKER_CURL,
  IP_PRIMARY,
  IP_MOBILE_SWITCH,
  IP_ATTACKER_FOREIGN,
  IP_ATTACKER_SAME_SUBNET
};

