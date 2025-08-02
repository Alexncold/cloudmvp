// Global setup for all tests
const fs = require('fs');
const path = require('path');

async function globalSetup() {
  // Create test storage directory if it doesn't exist
  const testStoragePath = path.join(__dirname, 'test-storage');
  try {
    if (!fs.existsSync(testStoragePath)) {
      fs.mkdirSync(testStoragePath, { recursive: true });
      console.log(`Test storage directory created at: ${testStoragePath}`);
    }
  } catch (error) {
    console.error('Error creating test storage directory:', error);
    throw error; // Rethrow to fail the test setup
  }

  // Set environment variables
  process.env.NODE_ENV = 'test';
  process.env.STORAGE_DIR = testStoragePath;
  process.env.SEGMENT_DURATION = '10';
  process.env.SEGMENT_RETENTION_DAYS = '7';
  process.env.JWT_SECRET = 'test-secret';
  process.env.JWT_EXPIRES_IN = '1h';
  
  console.log('Global test setup completed');
}

module.exports = globalSetup;
