const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { generateAccounts, seedAccounts, BASE_URL } = require('./accounts');
const { runCalibration } = require('./calibrator');
const { SCENARIOS } = require('./scenarios');
const { runS9LoadTest } = require('./scenarios/s9_load');
const { generateReport } = require('./reporter');

const METHODS = ['token-only', 'network-binding', 'network-ua', 'session-guard'];

async function runEvaluationSuite() {
  console.log('================================================================');
  console.log('    SessionGuard Full Automated Evaluation Benchmark Suite       ');
  console.log('================================================================');

  // 1. Reset server databases & mail sink for clean run
  try {
    await axios.post(`${BASE_URL}/api/debug/reset`);
    console.log('Backend databases and mail sink reset.');
  } catch (err) {
    console.warn('Could not reset server state (is backend running?):', err.message);
  }

  // 2. Generate and seed synthetic accounts
  const TOTAL_ACCOUNTS = 60;
  const allAccounts = generateAccounts(TOTAL_ACCOUNTS);
  await seedAccounts(allAccounts, BASE_URL);
  console.log(`Successfully generated and seeded ${TOTAL_ACCOUNTS} synthetic accounts.`);

  // Disjoint partition split: 30% calibration (18 accounts), 70% evaluation (42 accounts)
  const CALIBRATION_COUNT = 18;
  const calibrationAccounts = allAccounts.slice(0, CALIBRATION_COUNT);
  const evaluationAccounts = allAccounts.slice(CALIBRATION_COUNT);

  console.log(`Partition Split:`);
  console.log(`  - Calibration Partition: ${calibrationAccounts.length} accounts (${calibrationAccounts[0].email} ... ${calibrationAccounts[calibrationAccounts.length - 1].email})`);
  console.log(`  - Evaluation Partition:  ${evaluationAccounts.length} accounts (${evaluationAccounts[0].email} ... ${evaluationAccounts[evaluationAccounts.length - 1].email})\n`);

  // 3. Calibration Phase
  const calibratedConfig = await runCalibration(BASE_URL, calibrationAccounts);

  // 4. Evaluation Phase on Evaluation Partition
  console.log('================================================================');
  console.log(' Starting Evaluation Phase (Disjoint Evaluation Partition)     ');
  console.log(` Evaluating 4 Methods across 8 Scenarios (S1 - S8)              `);
  console.log('================================================================\n');

  const rawRuns = [];
  const TRIALS_PER_SCENARIO = 15; // 15 trials per scenario per method = 15 * 8 * 4 = 480 runs

  const csvRows = [
    'run_id,scenario_id,scenario_name,ground_truth,method,decision,is_correct,risk_score,detection_latency_ms,time_to_containment_ms,notification_latency_ms,timestamp'
  ];

  let runCounter = 1;

  for (const method of METHODS) {
    console.log(`\n>>> Evaluating Method: [${method.toUpperCase()}] <<<`);
    // Ensure all account passwords and state are fresh for this method
    await seedAccounts(allAccounts, BASE_URL);

    for (const scenario of SCENARIOS) {
      process.stdout.write(`  Running ${scenario.id} (${TRIALS_PER_SCENARIO} trials)... `);
      let passedTrials = 0;

      for (let t = 0; t < TRIALS_PER_SCENARIO; t++) {
        // Pick account deterministically from evaluation partition
        const accIndex = (t % evaluationAccounts.length);
        const account = evaluationAccounts[accIndex];

        try {
          const runRes = await scenario.fn(BASE_URL, account, method);
          passedTrials++;

          const runRecord = {
            runId: `run_${runCounter++}`,
            scenarioId: runRes.scenarioId,
            scenarioName: runRes.scenarioName,
            groundTruth: runRes.groundTruth,
            method,
            decision: runRes.decision,
            isCorrect: runRes.isCorrect,
            riskScore: runRes.score !== undefined ? runRes.score : null,
            detectionLatencyMs: runRes.detectionLatencyMs,
            timeToContainmentMs: runRes.timeToContainmentMs,
            notificationLatencyMs: runRes.notificationLatencyMs,
            timestamp: new Date().toISOString()
          };

          rawRuns.push(runRecord);

          csvRows.push([
            runRecord.runId,
            runRecord.scenarioId,
            `"${runRecord.scenarioName}"`,
            runRecord.groundTruth,
            runRecord.method,
            runRecord.decision,
            runRecord.isCorrect ? 1 : 0,
            runRecord.riskScore !== null ? runRecord.riskScore : '',
            runRecord.detectionLatencyMs !== null ? runRecord.detectionLatencyMs.toFixed(2) : '',
            runRecord.timeToContainmentMs !== null ? runRecord.timeToContainmentMs.toFixed(2) : '',
            runRecord.notificationLatencyMs !== null ? runRecord.notificationLatencyMs.toFixed(2) : '',
            runRecord.timestamp
          ].join(','));

        } catch (err) {
          console.error(`\nError in ${scenario.id} trial ${t}:`, err.message);
        }
      }
      console.log(`Done (${passedTrials}/${TRIALS_PER_SCENARIO}).`);
    }
  }

  // Save CSV and JSON
  const rawDir = path.join(__dirname, '../../results/raw');
  fs.mkdirSync(rawDir, { recursive: true });

  const csvPath = path.join(rawDir, 'evaluation_runs.csv');
  fs.writeFileSync(csvPath, csvRows.join('\n'), 'utf8');

  const jsonPath = path.join(rawDir, 'evaluation_runs.json');
  fs.writeFileSync(jsonPath, JSON.stringify(rawRuns, null, 2), 'utf8');

  console.log(`\nEvaluation runs saved to ${csvPath} (${rawRuns.length} total runs logged).`);

  // 5. Fetch Postgres Audit Logs
  try {
    const auditRes = await axios.get(`${BASE_URL}/api/debug/audit-logs`);
    fs.writeFileSync(
      path.join(rawDir, 'audit_logs.json'),
      JSON.stringify(auditRes.data, null, 2)
    );
    console.log(`Audit logs snapshot saved (${auditRes.data.count} records).`);
  } catch (err) {
    console.warn('Could not export audit logs:', err.message);
  }

  // 6. Run S9 Load Test
  const loadTestAccount = evaluationAccounts[0];
  const loadResults = await runS9LoadTest(BASE_URL, loadTestAccount);

  // 7. Generate Tables I - IV and SVG Figures 4 & 5
  console.log('\n================================================================');
  console.log(' Generating Result Tables I-IV and Figures 4-5 from Real Data   ');
  console.log('================================================================\n');

  await generateReport({
    rawRuns,
    loadResults,
    calibratedConfig
  });

  console.log('\n================================================================');
  console.log(' Benchmark and Report Generation Completed Successfully!       ');
  console.log('================================================================\n');
}

if (require.main === module) {
  runEvaluationSuite().catch(err => {
    console.error('Evaluation suite encountered fatal error:', err);
    process.exit(1);
  });
}

module.exports = {
  runEvaluationSuite
};
