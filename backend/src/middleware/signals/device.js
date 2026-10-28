const SessionManager = require('../../models/session');

/**
 * Signal f_D: Client/device/header consistency vs. baseline
 * Output: [0.0, 1.0]
 * 0.0 = exact match
 * 0.3 - 0.4 = minor header variance, same platform & browser
 * 1.0 = major mismatch (different OS, browser, or stripped headers)
 */
function extractDeviceSignal(headers, baseline) {
  if (!baseline || !baseline.headerHash) {
    return 0.0;
  }

  const currentHash = SessionManager.hashClientHeaders(headers);
  if (currentHash === baseline.headerHash) {
    return 0.0;
  }

  const currentUa = (headers['user-agent'] || '').toLowerCase();
  const baselineUa = (baseline.userAgent || '').toLowerCase();

  // If UA is identical, but other headers changed slightly
  if (currentUa === baselineUa) {
    return 0.2;
  }

  // Detect platform and browser
  const getFingerprint = (ua) => {
    let os = 'unknown';
    if (ua.includes('windows')) os = 'windows';
    else if (ua.includes('macintosh') || ua.includes('mac os')) os = 'mac';
    else if (ua.includes('linux')) os = 'linux';
    else if (ua.includes('iphone') || ua.includes('ipad')) os = 'ios';
    else if (ua.includes('android')) os = 'android';

    let browser = 'other';
    if (ua.includes('edg/')) browser = 'edge';
    else if (ua.includes('chrome/')) browser = 'chrome';
    else if (ua.includes('firefox/')) browser = 'firefox';
    else if (ua.includes('safari/') && !ua.includes('chrome')) browser = 'safari';
    else if (ua.includes('curl') || ua.includes('python') || ua.includes('axios')) browser = 'automated_tool';

    return { os, browser };
  };

  const currentFp = getFingerprint(currentUa);
  const baselineFp = getFingerprint(baselineUa);

  // If automated tool or completely different OS & browser
  if (currentFp.browser === 'automated_tool' || baselineFp.browser === 'automated_tool') {
    return 1.0;
  }

  if (currentFp.os === baselineFp.os && currentFp.browser === baselineFp.browser) {
    // Same OS & browser family, version variation
    return 0.35;
  }

  if (currentFp.os === baselineFp.os) {
    // Same OS, different browser
    return 0.7;
  }

  // Entirely different device / OS
  return 1.0;
}

module.exports = {
  extractDeviceSignal
};

