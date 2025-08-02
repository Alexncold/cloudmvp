// Simple test to check Node.js execution
console.log('This is a simple test to check Node.js execution');

const test = () => {
  console.log('Running test function...');
  return 'Test completed';
};

const result = test();
console.log('Test result:', result);

// Add a simple assertion
const assert = require('assert');
assert.strictEqual(1 + 1, 2, '1+1 should equal 2');
console.log('Assertion passed!');
