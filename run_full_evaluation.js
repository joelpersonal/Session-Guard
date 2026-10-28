const { startServer, stopServer } = require('./backend/src/server');
const { runEvaluationSuite } = require('./harness/src/runner');

async function main() {
  console.log('>>> [1/3] Starting SessionGuard Backend & Mock Mail Sink...');
  const server = await startServer(5000);

  try {
    console.log('>>> [2/3] Backend active. Initiating Full Automated Experiment Benchmark...');
    await runEvaluationSuite();
    console.log('>>> [3/3] Full evaluation benchmark completed successfully!');
  } catch (err) {
    console.error('Fatal benchmark error:', err);
  } finally {
    console.log('>>> Shutting down test server instances...');
    stopServer();
    process.exit(0);
  }
}

main();

