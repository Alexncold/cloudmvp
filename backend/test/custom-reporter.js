// A custom Jest reporter that logs test results
class CustomReporter {
  constructor(globalConfig, options) {
    this._globalConfig = globalConfig;
    this._options = options;
  }

  onRunStart() {
    console.log('CustomReporter: Test run started');
  }

  onTestStart(test) {
    console.log(`CustomReporter: Test started: ${test.path}`);
  }

  onTestResult(test, testResult) {
    console.log(`CustomReporter: Test completed: ${testResult.testFilePath}`);
    testResult.testResults.forEach(result => {
      console.log(`  - ${result.title}: ${result.status}`);
    });
  }

  onRunComplete(contexts, results) {
    console.log('CustomReporter: Test run completed');
    if (results) {
      console.log(`CustomReporter: Tests passed: ${results.numPassedTests}`);
      console.log(`CustomReporter: Tests failed: ${results.numFailedTests}`);
    }
  }
}

module.exports = CustomReporter;
