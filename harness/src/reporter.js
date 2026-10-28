const fs = require('fs');
const path = require('path');

function calcMeanStd(values) {
  const valid = values.filter(v => v !== null && v !== undefined && !isNaN(v));
  if (valid.length === 0) return { mean: 0, std: 0, count: 0 };
  const mean = valid.reduce((a, b) => a + b, 0) / valid.length;
  const variance = valid.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / valid.length;
  return { mean, std: Math.sqrt(variance), count: valid.length };
}

function formatMeanStd(obj, unit = 'ms') {
  if (obj.count === 0) return 'n/a';
  return `${obj.mean.toFixed(2)} ± ${obj.std.toFixed(2)} ${unit}`;
}

async function generateReport({ rawRuns, loadResults, calibratedConfig }) {
  const outDir = path.join(__dirname, '../../results');
  fs.mkdirSync(outDir, { recursive: true });

  const methods = ['token-only', 'network-binding', 'network-ua', 'session-guard'];
  const methodLabels = {
    'token-only': 'Token-Only',
    'network-binding': 'Network Binding',
    'network-ua': 'Network + User-Agent',
    'session-guard': 'SessionGuard'
  };

  // ==========================================
  // TABLE I: Overall Detection Performance
  // ==========================================
  const table1Stats = {};

  for (const method of methods) {
    const methodRuns = rawRuns.filter(r => r.method === method);
    let tp = 0, fp = 0, tn = 0, fn = 0;

    for (const r of methodRuns) {
      if (r.groundTruth === 'attack') {
        if (r.isCorrect) tp++;
        else fn++;
      } else {
        if (r.isCorrect) tn++;
        else fp++;
      }
    }

    const precision = (tp + fp) > 0 ? (tp / (tp + fp)) : 0;
    const recall = (tp + fn) > 0 ? (tp / (tp + fn)) : 0;
    const f1 = (precision + recall) > 0 ? (2 * precision * recall / (precision + recall)) : 0;
    const fpr = (fp + tn) > 0 ? (fp / (fp + tn)) : 0;

    table1Stats[method] = {
      label: methodLabels[method],
      tp, fp, tn, fn,
      total: methodRuns.length,
      recall,
      precision,
      f1,
      fpr
    };
  }

  let table1Md = `# TABLE I: Detection Performance Across Methods (Evaluation Partition)\n\n`;
  table1Md += `*Data Source: \`results/raw/evaluation_runs.csv\` | Total Evaluated Rows: ${rawRuns.length}*\n\n`;
  table1Md += `| Method | TP | FP | TN | FN | Detection Rate (Recall) | Precision | F1 Score | FP Rate |\n`;
  table1Md += `| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n`;

  for (const m of methods) {
    const s = table1Stats[m];
    table1Md += `| **${s.label}** | ${s.tp} | ${s.fp} | ${s.tn} | ${s.fn} | ${(s.recall * 100).toFixed(1)}% | ${(s.precision * 100).toFixed(1)}% | ${s.f1.toFixed(3)} | ${(s.fpr * 100).toFixed(1)}% |\n`;
  }

  fs.writeFileSync(path.join(outDir, 'table_1_detection_performance.md'), table1Md, 'utf8');

  // ==========================================
  // TABLE II: Breakdown by Scenario (S1 - S8)
  // ==========================================
  const scenarioIds = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8'];
  const scenarioNames = {
    'S1': 'Normal session (no anomalies)',
    'S2': 'Legitimate network change mid-session',
    'S3': 'Stolen token: Foreign network + foreign UA (A1)',
    'S4': 'Stolen token: Same network + spoofed UA (A2)',
    'S5': 'Concurrent interleaved credential use (D1↔D2)',
    'S6': 'Sensitive action from anomalous context',
    'S7': 'Legitimate sensitive action (benign check)',
    'S8': 'Legitimate multi-device sequential (benign check)'
  };
  const scenarioGroundTruth = {
    'S1': 'Benign', 'S2': 'Benign', 'S3': 'Attack', 'S4': 'Attack',
    'S5': 'Attack', 'S6': 'Attack', 'S7': 'Benign', 'S8': 'Benign'
  };

  let table2Md = `# TABLE II: Performance Breakdown by Scenario (S1–S8)\n\n`;
  table2Md += `*Data Source: \`results/raw/evaluation_runs.csv\` | Total Evaluated Rows: ${rawRuns.length}*\n\n`;
  table2Md += `| Scenario | Description | Ground Truth | Token-Only | Network Binding | Network + UA | SessionGuard |\n`;
  table2Md += `| :--- | :--- | :---: | :---: | :---: | :---: | :---: |\n`;

  for (const sid of scenarioIds) {
    const rowCells = [sid, scenarioNames[sid], scenarioGroundTruth[sid]];

    for (const m of methods) {
      const runs = rawRuns.filter(r => r.scenarioId === sid && r.method === m);
      const correctCount = runs.filter(r => r.isCorrect).length;
      const rate = runs.length > 0 ? (correctCount / runs.length) * 100 : 0;
      const gt = scenarioGroundTruth[sid];

      let tag = '';
      if (gt === 'Attack') {
        tag = rate >= 90 ? `✓ Detected (${rate.toFixed(0)}%)` : `✗ Missed (${(100 - rate).toFixed(0)}% FN)`;
      } else {
        tag = rate >= 90 ? `✓ Allowed (${rate.toFixed(0)}%)` : `✗ Blocked (${(100 - rate).toFixed(0)}% FP)`;
      }
      rowCells.push(tag);
    }

    table2Md += `| **${rowCells[0]}** | ${rowCells[1]} | ${rowCells[2]} | ${rowCells[3]} | ${rowCells[4]} | ${rowCells[5]} | ${rowCells[6]} |\n`;
  }

  fs.writeFileSync(path.join(outDir, 'table_2_scenario_breakdown.md'), table2Md, 'utf8');

  // ==========================================
  // TABLE III: Latency & Containment Timings
  // ==========================================
  const table3Timings = {};
  for (const m of methods) {
    const detectedRuns = rawRuns.filter(r => r.method === m && r.detectionLatencyMs !== null);
    const containedRuns = rawRuns.filter(r => r.method === m && r.timeToContainmentMs !== null);
    const notifRuns = rawRuns.filter(r => r.method === m && r.notificationLatencyMs !== null);

    table3Timings[m] = {
      detection: calcMeanStd(detectedRuns.map(r => r.detectionLatencyMs)),
      containment: calcMeanStd(containedRuns.map(r => r.timeToContainmentMs)),
      notification: calcMeanStd(notifRuns.map(r => r.notificationLatencyMs))
    };
  }

  let table3Md = `# TABLE III: Latency and Containment Timings\n\n`;
  table3Md += `*Data Source: \`results/raw/evaluation_runs.csv\` | Measured on active local server*\n\n`;
  table3Md += `| Metric | Token-Only | Network Binding | Network + User-Agent | SessionGuard |\n`;
  table3Md += `| :--- | :---: | :---: | :---: | :---: |\n`;

  table3Md += `| **Detection Latency (ms)** | n/a (No Detection) | ${formatMeanStd(table3Timings['network-binding'].detection)} | ${formatMeanStd(table3Timings['network-ua'].detection)} | ${formatMeanStd(table3Timings['session-guard'].detection)} |\n`;
  table3Md += `| **Time-to-Containment (ms)** | unbounded (n/a) | unbounded (n/a)* | unbounded (n/a)* | ${formatMeanStd(table3Timings['session-guard'].containment)} |\n`;
  table3Md += `| **Notification Latency (ms)** | n/a | n/a | n/a | ${formatMeanStd(table3Timings['session-guard'].notification)} |\n\n`;
  table3Md += `*\*Note: Baseline methods (Network Binding, Network+UA) reject the immediate HTTP request but have no session-revocation engine or refresh-token family invalidator, leaving the stolen credential unbounded/valid in Redis for future requests.*\n`;

  fs.writeFileSync(path.join(outDir, 'table_3_latency_timings.md'), table3Md, 'utf8');

  // ==========================================
  // TABLE IV: Scalability and Runtime Overhead (S9)
  // ==========================================
  let table4Md = `# TABLE IV: Scalability and Runtime Overhead (S9 Load Test)\n\n`;
  table4Md += `*Data Source: \`results/raw/load_test_results.json\` | Evaluated with autocannon across concurrency tiers*\n\n`;
  table4Md += `| Concurrent Sessions | Baseline (Off) Mean Latency | Baseline (Off) p95 Latency | Baseline Req/s | SessionGuard Mean Latency | SessionGuard p95 Latency | SessionGuard Req/s | Overhead (Mean Δ) | Overhead (p95 Δ) | % Overhead | CPU (%) | Memory (MB) |\n`;
  table4Md += `| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n`;

  for (const row of loadResults) {
    table4Md += `| **${row.concurrency.toLocaleString()}** | ${row.off.meanLatencyMs.toFixed(2)} ms | ${row.off.p95LatencyMs.toFixed(2)} ms | ${row.off.reqPerSec.toLocaleString()} | ${row.on.meanLatencyMs.toFixed(2)} ms | ${row.on.p95LatencyMs.toFixed(2)} ms | ${row.on.reqPerSec.toLocaleString()} | +${row.overhead.deltaMeanMs.toFixed(2)} ms | +${row.overhead.deltaP95Ms.toFixed(2)} ms | +${row.overhead.overheadPercent.toFixed(1)}% | ${row.system.cpuPercent}% | ${row.system.memoryMb} MB |\n`;
  }

  fs.writeFileSync(path.join(outDir, 'table_4_load_overhead.md'), table4Md, 'utf8');

  // ==========================================
  // FIGURES 4 & 5: SVG Charts
  // ==========================================
  generateFig4Svg(loadResults, path.join(outDir, 'fig_4_latency_overhead.svg'));
  generateFig5Svg(table1Stats, path.join(outDir, 'fig_5_roc_detection.svg'));

  console.log('Result artifacts successfully written:');
  console.log('  - results/table_1_detection_performance.md');
  console.log('  - results/table_2_scenario_breakdown.md');
  console.log('  - results/table_3_latency_timings.md');
  console.log('  - results/table_4_load_overhead.md');
  console.log('  - results/fig_4_latency_overhead.svg');
  console.log('  - results/fig_5_roc_detection.svg');
}

/**
 * Figure 4: Latency & Runtime Overhead vs Concurrency
 */
function generateFig4Svg(loadResults, destPath) {
  const width = 800;
  const height = 450;
  const margin = { top: 50, right: 120, bottom: 60, left: 70 };
  const plotW = width - margin.left - margin.right;
  const plotH = height - margin.top - margin.bottom;

  const maxConcurrency = Math.max(...loadResults.map(r => r.concurrency));
  const maxLat = Math.max(...loadResults.map(r => Math.max(r.off.p95LatencyMs, r.on.p95LatencyMs))) * 1.25;

  const getX = (c) => margin.left + (Math.log10(c) - 2) / (Math.log10(10000) - 2) * plotW;
  const getY = (val) => margin.top + plotH - (val / maxLat) * plotH;

  let offPoints = loadResults.map(r => `${getX(r.concurrency).toFixed(1)},${getY(r.off.meanLatencyMs).toFixed(1)}`).join(' ');
  let onPoints = loadResults.map(r => `${getX(r.concurrency).toFixed(1)},${getY(r.on.meanLatencyMs).toFixed(1)}`).join(' ');
  let onP95Points = loadResults.map(r => `${getX(r.concurrency).toFixed(1)},${getY(r.on.p95LatencyMs).toFixed(1)}`).join(' ');

  const svg = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
  <rect width="${width}" height="${height}" fill="#0f172a" rx="10"/>
  <text x="${width/2}" y="32" fill="#38bdf8" font-size="18" font-weight="bold" text-anchor="middle" font-family="sans-serif">
    Figure 4: Scalability &amp; Request Latency Overhead (Middleware ON vs. OFF)
  </text>
  
  <!-- Grid lines -->
  <line x1="${margin.left}" y1="${getY(0)}" x2="${margin.left + plotW}" y2="${getY(0)}" stroke="#334155" stroke-width="1.5"/>
  <line x1="${margin.left}" y1="${getY(maxLat*0.25)}" x2="${margin.left + plotW}" y2="${getY(maxLat*0.25)}" stroke="#1e293b" stroke-dasharray="4"/>
  <line x1="${margin.left}" y1="${getY(maxLat*0.5)}" x2="${margin.left + plotW}" y2="${getY(maxLat*0.5)}" stroke="#1e293b" stroke-dasharray="4"/>
  <line x1="${margin.left}" y1="${getY(maxLat*0.75)}" x2="${margin.left + plotW}" y2="${getY(maxLat*0.75)}" stroke="#1e293b" stroke-dasharray="4"/>
  
  <!-- Y Axis Labels -->
  <text x="${margin.left - 12}" y="${getY(0)}" fill="#94a3b8" font-size="12" text-anchor="end" font-family="sans-serif">0ms</text>
  <text x="${margin.left - 12}" y="${getY(maxLat*0.5)}" fill="#94a3b8" font-size="12" text-anchor="end" font-family="sans-serif">${(maxLat*0.5).toFixed(1)}ms</text>
  <text x="${margin.left - 12}" y="${getY(maxLat)}" fill="#94a3b8" font-size="12" text-anchor="end" font-family="sans-serif">${maxLat.toFixed(1)}ms</text>
  <text x="24" y="${margin.top + plotH/2}" fill="#94a3b8" font-size="13" transform="rotate(-90 24 ${margin.top + plotH/2})" text-anchor="middle" font-family="sans-serif">Latency (ms)</text>

  <!-- X Axis Labels -->
  ${loadResults.map(r => `
    <line x1="${getX(r.concurrency)}" y1="${margin.top + plotH}" x2="${getX(r.concurrency)}" y2="${margin.top + plotH + 6}" stroke="#475569"/>
    <text x="${getX(r.concurrency)}" y="${margin.top + plotH + 22}" fill="#94a3b8" font-size="12" text-anchor="middle" font-family="sans-serif">${r.concurrency >= 1000 ? (r.concurrency/1000) + 'k' : r.concurrency}</text>
  `).join('')}
  <text x="${margin.left + plotW/2}" y="${height - 15}" fill="#94a3b8" font-size="13" text-anchor="middle" font-family="sans-serif">Concurrent Active Sessions (Log Scale)</text>

  <!-- Lines -->
  <polyline points="${offPoints}" fill="none" stroke="#94a3b8" stroke-width="2.5" stroke-dasharray="6"/>
  <polyline points="${onPoints}" fill="none" stroke="#38bdf8" stroke-width="3"/>
  <polyline points="${onP95Points}" fill="none" stroke="#f59e0b" stroke-width="2.5"/>

  <!-- Data dots -->
  ${loadResults.map(r => `
    <circle cx="${getX(r.concurrency)}" cy="${getY(r.off.meanLatencyMs)}" r="5" fill="#94a3b8"/>
    <circle cx="${getX(r.concurrency)}" cy="${getY(r.on.meanLatencyMs)}" r="5" fill="#38bdf8"/>
    <circle cx="${getX(r.concurrency)}" cy="${getY(r.on.p95LatencyMs)}" r="5" fill="#f59e0b"/>
  `).join('')}

  <!-- Legend -->
  <rect x="${width - 165}" y="${margin.top + 10}" width="150" height="95" fill="#1e293b" rx="6" stroke="#334155"/>
  <line x1="${width - 150}" y1="${margin.top + 30}" x2="${width - 130}" y2="${margin.top + 30}" stroke="#94a3b8" stroke-width="2.5" stroke-dasharray="4"/>
  <text x="${width - 120}" y="${margin.top + 34}" fill="#e2e8f0" font-size="11" font-family="sans-serif">Off: Mean</text>
  <line x1="${width - 150}" y1="${margin.top + 55}" x2="${width - 130}" y2="${margin.top + 55}" stroke="#38bdf8" stroke-width="3"/>
  <text x="${width - 120}" y="${margin.top + 59}" fill="#38bdf8" font-size="11" font-family="sans-serif">SG: Mean</text>
  <line x1="${width - 150}" y1="${margin.top + 80}" x2="${width - 130}" y2="${margin.top + 80}" stroke="#f59e0b" stroke-width="2.5"/>
  <text x="${width - 120}" y="${margin.top + 84}" fill="#f59e0b" font-size="11" font-family="sans-serif">SG: p95</text>
</svg>
  `.trim();

  fs.writeFileSync(destPath, svg, 'utf8');
}

/**
 * Figure 5: Detection Rate (Recall) vs False Positive Rate
 */
function generateFig5Svg(table1Stats, destPath) {
  const width = 800;
  const height = 450;
  const margin = { top: 50, right: 80, bottom: 60, left: 80 };
  const plotW = width - margin.left - margin.right;
  const plotH = height - margin.top - margin.bottom;

  const getX = (fpr) => margin.left + (fpr) * plotW;
  const getY = (rec) => margin.top + plotH - (rec) * plotH;

  const methods = [
    { key: 'token-only', name: 'Token-Only', color: '#64748b', x: table1Stats['token-only'].fpr, y: table1Stats['token-only'].recall },
    { key: 'network-binding', name: 'Network Binding', color: '#ef4444', x: table1Stats['network-binding'].fpr, y: table1Stats['network-binding'].recall },
    { key: 'network-ua', name: 'Network + UA', color: '#f59e0b', x: table1Stats['network-ua'].fpr, y: table1Stats['network-ua'].recall },
    { key: 'session-guard', name: 'SessionGuard', color: '#10b981', x: table1Stats['session-guard'].fpr, y: table1Stats['session-guard'].recall }
  ];

  const svg = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">
  <rect width="${width}" height="${height}" fill="#0f172a" rx="10"/>
  <text x="${width/2}" y="32" fill="#38bdf8" font-size="18" font-weight="bold" text-anchor="middle" font-family="sans-serif">
    Figure 5: Detection Rate (Recall) vs. False Positive Rate Across Methods
  </text>
  
  <!-- Plot area boundary -->
  <rect x="${margin.left}" y="${margin.top}" width="${plotW}" height="${plotH}" fill="#1e293b" stroke="#334155"/>

  <!-- Ideal Target Quadrant (Top Left: High Recall, Low FPR) -->
  <rect x="${margin.left}" y="${margin.top}" width="${plotW * 0.15}" height="${plotH * 0.15}" fill="rgba(16, 185, 129, 0.15)" stroke="#10b981" stroke-dasharray="4"/>
  <text x="${margin.left + 8}" y="${margin.top + 20}" fill="#10b981" font-size="11" font-family="sans-serif">Optimal Zone</text>

  <!-- Grid lines -->
  <line x1="${getX(0.25)}" y1="${margin.top}" x2="${getX(0.25)}" y2="${margin.top + plotH}" stroke="#334155" stroke-dasharray="3"/>
  <line x1="${getX(0.50)}" y1="${margin.top}" x2="${getX(0.50)}" y2="${margin.top + plotH}" stroke="#334155" stroke-dasharray="3"/>
  <line x1="${getX(0.75)}" y1="${margin.top}" x2="${getX(0.75)}" y2="${margin.top + plotH}" stroke="#334155" stroke-dasharray="3"/>

  <line x1="${margin.left}" y1="${getY(0.25)}" x2="${margin.left + plotW}" y2="${getY(0.25)}" stroke="#334155" stroke-dasharray="3"/>
  <line x1="${margin.left}" y1="${getY(0.50)}" x2="${margin.left + plotW}" y2="${getY(0.50)}" stroke="#334155" stroke-dasharray="3"/>
  <line x1="${margin.left}" y1="${getY(0.75)}" x2="${margin.left + plotW}" y2="${getY(0.75)}" stroke="#334155" stroke-dasharray="3"/>

  <!-- Axis ticks & labels -->
  <text x="${margin.left}" y="${margin.top + plotH + 20}" fill="#94a3b8" font-size="12" text-anchor="middle" font-family="sans-serif">0.0</text>
  <text x="${getX(0.25)}" y="${margin.top + plotH + 20}" fill="#94a3b8" font-size="12" text-anchor="middle" font-family="sans-serif">0.25</text>
  <text x="${getX(0.50)}" y="${margin.top + plotH + 20}" fill="#94a3b8" font-size="12" text-anchor="middle" font-family="sans-serif">0.50</text>
  <text x="${getX(0.75)}" y="${margin.top + plotH + 20}" fill="#94a3b8" font-size="12" text-anchor="middle" font-family="sans-serif">0.75</text>
  <text x="${margin.left + plotW}" y="${margin.top + plotH + 20}" fill="#94a3b8" font-size="12" text-anchor="middle" font-family="sans-serif">1.0</text>
  <text x="${margin.left + plotW/2}" y="${height - 15}" fill="#94a3b8" font-size="13" text-anchor="middle" font-family="sans-serif">False Positive Rate (FPR)</text>

  <text x="${margin.left - 12}" y="${getY(0)}" fill="#94a3b8" font-size="12" text-anchor="end" font-family="sans-serif">0%</text>
  <text x="${margin.left - 12}" y="${getY(0.5)}" fill="#94a3b8" font-size="12" text-anchor="end" font-family="sans-serif">50%</text>
  <text x="${margin.left - 12}" y="${getY(1.0)}" fill="#94a3b8" font-size="12" text-anchor="end" font-family="sans-serif">100%</text>
  <text x="24" y="${margin.top + plotH/2}" fill="#94a3b8" font-size="13" transform="rotate(-90 24 ${margin.top + plotH/2})" text-anchor="middle" font-family="sans-serif">Detection Rate (Recall)</text>

  <!-- Method Scatter Points & Callouts -->
  ${methods.map(m => `
    <circle cx="${getX(m.x)}" cy="${getY(m.y)}" r="9" fill="${m.color}" stroke="#ffffff" stroke-width="2"/>
    <text x="${getX(m.x) + 14}" y="${getY(m.y) + 4}" fill="${m.color}" font-size="13" font-weight="bold" font-family="sans-serif">
      ${m.name} (${(m.y * 100).toFixed(0)}% Det, ${(m.x * 100).toFixed(0)}% FPR)
    </text>
  `).join('')}
</svg>
  `.trim();

  fs.writeFileSync(destPath, svg, 'utf8');
}

module.exports = {
  generateReport
};

