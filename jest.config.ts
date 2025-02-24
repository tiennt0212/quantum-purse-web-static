module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  testMatch: ['**/*.test.ts'],
  setupFilesAfterEnv: ["<rootDir>/jest.setup.ts"]
};