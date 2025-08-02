// Global teardown for all tests
const fs = require('fs');
const path = require('path');

async function globalTeardown() {
  // Clean up test storage directory
  const testStoragePath = path.join(__dirname, 'test-storage');
  try {
    if (fs.existsSync(testStoragePath)) {
      fs.rmSync(testStoragePath, { recursive: true, force: true });
      console.log(`Test storage directory cleaned: ${testStoragePath}`);
    }
  } catch (error) {
    console.error('Error cleaning test storage directory:', error);
    throw error; // Rethrow to fail the test teardown
  }
  
  console.log('Global test teardown completed');
}

module.exports = globalTeardown;
