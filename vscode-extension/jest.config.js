module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleNameMapper: {
    vscode: '<rootDir>/src/__mocks__/vscode.ts',
  },
  collectCoverageFrom: [
    'src/validation/YamlStructureValidator.ts',
    'src/validation/RuleLogicAnalyzer.ts',
    'src/validation/types.ts',
  ],
  coverageThreshold: {
    global: {
      branches: 75,
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
};
