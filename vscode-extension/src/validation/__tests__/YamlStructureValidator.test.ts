/**
 * Tests for YamlStructureValidator.
 * Every test case is grounded in a specific Pydantic constraint from srp/policy.py.
 */

import * as vscode from 'vscode';
import { YamlStructureValidator } from '../YamlStructureValidator';

// Mock vscode module — not available in Jest
jest.mock('vscode', () => ({
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
}), { virtual: true });

const validator = new YamlStructureValidator();

function errors(yaml: string) {
  return validator.validate(yaml).filter(d => d.severity === vscode.DiagnosticSeverity.Error);
}

function warnings(yaml: string) {
  return validator.validate(yaml).filter(d => d.severity === vscode.DiagnosticSeverity.Warning);
}

function codes(yaml: string) {
  return validator.validate(yaml).map(d => d.code);
}

// ── Valid policy ──────────────────────────────────────────────────────────────

const VALID_POLICY = `
name: test-policy
version: "1.0.0"
rules:
  - id: block-delete
    description: "Block delete operations"
    effect: BLOCK
    priority: 100
    condition:
      operations:
        - delete
`;

test('valid policy produces no diagnostics', () => {
  expect(validator.validate(VALID_POLICY)).toHaveLength(0);
});

// ── YAML parse errors ─────────────────────────────────────────────────────────

test('invalid YAML produces YAML_PARSE_ERROR', () => {
  expect(codes('name: [unclosed')).toContain('YAML_PARSE_ERROR');
});

// ── Top-level required fields ─────────────────────────────────────────────────
// Mirrors PolicySet required fields

test('missing name produces MISSING_REQUIRED_FIELD', () => {
  const yaml = `version: "1.0.0"\nrules: []`;
  expect(codes(yaml)).toContain('MISSING_REQUIRED_FIELD');
});

test('missing version produces MISSING_REQUIRED_FIELD', () => {
  const yaml = `name: test\nrules: []`;
  expect(codes(yaml)).toContain('MISSING_REQUIRED_FIELD');
});

test('missing rules produces MISSING_REQUIRED_FIELD', () => {
  const yaml = `name: test\nversion: "1.0.0"`;
  expect(codes(yaml)).toContain('MISSING_REQUIRED_FIELD');
});

test('empty name produces INVALID_NAME', () => {
  const yaml = `name: ""\nversion: "1.0.0"\nrules: []`;
  expect(codes(yaml)).toContain('INVALID_NAME');
});

// ── Rules array ───────────────────────────────────────────────────────────────

test('empty rules array produces EMPTY_RULES warning', () => {
  const yaml = `name: test\nversion: "1.0.0"\nrules: []`;
  expect(warnings(yaml).map(d => d.code)).toContain('EMPTY_RULES');
});

test('rules not an array produces RULES_NOT_ARRAY', () => {
  const yaml = `name: test\nversion: "1.0.0"\nrules: "not-an-array"`;
  expect(codes(yaml)).toContain('RULES_NOT_ARRAY');
});

// ── Rule required fields ──────────────────────────────────────────────────────

test('rule missing id produces RULE_MISSING_FIELD', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - description: "test"
    effect: BLOCK
    condition: {}
`;
  expect(codes(yaml)).toContain('RULE_MISSING_FIELD');
});

test('rule missing effect produces RULE_MISSING_FIELD', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    condition: {}
`;
  expect(codes(yaml)).toContain('RULE_MISSING_FIELD');
});

// ── Effect validation ─────────────────────────────────────────────────────────
// Mirrors PolicyEffect enum: ALLOW | BLOCK | ESCALATE

test('invalid effect produces RULE_INVALID_EFFECT', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: DENY
    condition: {}
`;
  expect(codes(yaml)).toContain('RULE_INVALID_EFFECT');
});

test('lowercase effect is valid (YamlPolicyLoader calls .upper())', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: block
    condition:
      operations: [delete]
`;
  expect(errors(yaml)).toHaveLength(0);
});

// ── Condition validation ──────────────────────────────────────────────────────

test('unknown condition key produces CONDITION_UNKNOWN_KEY warning', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      unknown_field: [value]
`;
  expect(warnings(yaml).map(d => d.code)).toContain('CONDITION_UNKNOWN_KEY');
});

test('empty operations list produces CONDITION_EMPTY_LIST', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      operations: []
`;
  // conlist min_length=1
  expect(codes(yaml)).toContain('CONDITION_EMPTY_LIST');
});

test('invalid environment value produces CONDITION_INVALID_ENVIRONMENT', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      environments:
        - production
`;
  // Literal["dev","staging","prod"] — "production" is not valid
  expect(codes(yaml)).toContain('CONDITION_INVALID_ENVIRONMENT');
});

test('valid environments are accepted', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      environments:
        - dev
        - staging
        - prod
`;
  expect(errors(yaml)).toHaveLength(0);
});

test('max_numeric_parameters with non-number value produces error', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      max_numeric_parameters:
        amount: "not-a-number"
`;
  expect(codes(yaml)).toContain('CONDITION_MAX_NUMERIC_NOT_NUMBER');
});

test('max_numeric_parameters with number value is valid', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      max_numeric_parameters:
        amount: 10000.0
`;
  expect(errors(yaml)).toHaveLength(0);
});
