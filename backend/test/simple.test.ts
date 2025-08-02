// Simple test file to verify Jest execution

console.log('This is a test log message from simple.test.ts');

describe('Simple Test Suite', () => {
  it('should pass a simple test', () => {
    console.log('Running simple test...');
    expect(true).toBe(true);
  });

  it('should fail a simple test', () => {
    console.log('Running failing test...');
    expect(false).toBe(true);
  });
});
