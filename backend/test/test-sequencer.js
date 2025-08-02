// Custom test sequencer to control the order of test files
const Sequencer = require('@jest/test-sequencer').default;
const path = require('path');

class CustomSequencer extends Sequencer {
  sort(tests) {
    // Test order: setup tests first, then others, then teardown
    const orderedTests = [];
    const setupTests = [];
    const teardownTests = [];
    const otherTests = [];

    tests.forEach(test => {
      const basename = path.basename(test.path);
      if (basename.includes('setup') || basename.includes('init')) {
        setupTests.push(test);
      } else if (basename.includes('teardown') || basename.includes('cleanup')) {
        teardownTests.push(test);
      } else {
        otherTests.push(test);
      }
    });

    // Run setup tests first, then other tests, then teardown tests
    return [...setupTests, ...otherTests, ...teardownTests];
  }
}

module.exports = CustomSequencer;
