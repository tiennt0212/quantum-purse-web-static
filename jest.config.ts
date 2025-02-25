module.exports = {
  preset: 'ts-jest',
  testEnvironment: './jest.custom.env.js',
  testMatch: ['**/*.test.ts'],
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
};