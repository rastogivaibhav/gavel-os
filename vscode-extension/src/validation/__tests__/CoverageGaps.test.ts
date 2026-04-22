/**
 * CoverageGaps.test.ts — Targeted tests for uncovered branches.
 *
 * These tests cover the specific lines flagged by the coverage report:
 *   YamlStructureValidator: line 33 (NOT_A_MAPPING), lines 282-283 (CONDITION_FIELD_NOT_ARRAY)
 *   RuleLogicAnalyzer: lines 335-336, 376, 380 (conditionIsSubset edge cases)
 */

import * as vscode from 'vscode';
import { YamlStructureValidator } from '../YamlStructureValidator';
import { RuleLogicAnalyzer } from '../RuleLogicAnalyzer';

jest.mock('vscode', () => ({
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
}), { virtual: true });

const structureValidator = new YamlStructureValidator();
const logicAnalyzer = new RuleLogicAnalyzer();

function codes(text: string, validator: YamlStructureValidator | RuleLogicAnalyzer) {
  if (validator instanceof YamlStructureValidator) {
    return validator.validate(text).map(d => d.code);
  }
  return validator.analyze(text).map(d => d.code);
}

// ── YamlStructureValidator: NOT_A_MAPPING (line 33) ──────────────────────────
// Triggered when YAML parses to a non-object (array, string, number)

test('YAML that parses to an array produces NOT_A_MAPPING', () => {
  const yaml = `- item1\n- item2`;
  expect(codes(yaml, structureValidator)).toContain('NOT_A_MAPPING');
});

test('YAML that parses to a string produces NOT_A_MAPPING', () => {
  const yaml = `"just a string"`;
  expect(codes(yaml, structureValidator)).toContain('NOT_A_MAPPING');
});

// ── YamlStructureValidator: CONDITION_FIELD_NOT_ARRAY (lines 282-283) ────────
// Triggered when a list field (tenants, roles, etc.) is not an array

test('tenants as a string produces CONDITION_FIELD_NOT_ARRAY', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      tenants: "not-an-array"
`;
  expect(codes(yaml, structureValidator)).toContain('CONDITION_FIELD_NOT_ARRAY');
});

test('roles as a number produces CONDITION_FIELD_NOT_ARRAY', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      roles: 42
`;
  expect(codes(yaml, structureValidator)).toContain('CONDITION_FIELD_NOT_ARRAY');
});

test('api_refs as a mapping produces CONDITION_FIELD_NOT_ARRAY', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      api_refs:
        key: value
`;
  expect(codes(yaml, structureValidator)).toContain('CONDITION_FIELD_NOT_ARRAY');
});

// ── YamlStructureValidator: RULE_NOT_MAPPING ──────────────────────────────────
// Triggered when a rule entry is not a mapping

test('rule as a string produces RULE_NOT_MAPPING', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - "not-a-mapping"
`;
  expect(codes(yaml, structureValidator)).toContain('RULE_NOT_MAPPING');
});

// ── YamlStructureValidator: CONDITION_NOT_MAPPING ────────────────────────────

test('condition as a string produces CONDITION_NOT_MAPPING', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition: "not-a-mapping"
`;
  expect(codes(yaml, structureValidator)).toContain('CONDITION_NOT_MAPPING');
});

test('condition as an array produces CONDITION_NOT_MAPPING', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    condition:
      - item
`;
  expect(codes(yaml, structureValidator)).toContain('CONDITION_NOT_MAPPING');
});

// ── RuleLogicAnalyzer: conditionIsSubset with tenant/role fields ──────────────
// Lines 335-336: narrower has a field that broader also has but doesn't cover all values

test('rule with tenant subset is detected as unreachable', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: broad
    description: "matches tenants a and b"
    effect: BLOCK
    priority: 100
    condition:
      tenants: [tenant-a, tenant-b]
  - id: narrow
    description: "matches only tenant-a"
    effect: ALLOW
    priority: 200
    condition:
      tenants: [tenant-a]
`;
  expect(codes(yaml, logicAnalyzer)).toContain('UNREACHABLE_RULE');
});

test('rule with non-subset tenant is not unreachable', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: rule-a
    description: "matches tenant-a"
    effect: BLOCK
    priority: 100
    condition:
      tenants: [tenant-a]
  - id: rule-b
    description: "matches tenant-b"
    effect: ALLOW
    priority: 200
    condition:
      tenants: [tenant-b]
`;
  expect(codes(yaml, logicAnalyzer)).not.toContain('UNREACHABLE_RULE');
});

// ── RuleLogicAnalyzer: conditionsOverlap with roles ──────────────────────────
// Line 376: overlap check with roles field

test('same priority with overlapping roles produces PRIORITY_CONFLICT', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: rule-a
    description: "a"
    effect: BLOCK
    priority: 100
    condition:
      roles: [admin, customer]
  - id: rule-b
    description: "b"
    effect: ALLOW
    priority: 100
    condition:
      roles: [customer]
`;
  expect(codes(yaml, logicAnalyzer)).toContain('PRIORITY_CONFLICT');
});

// ── RuleLogicAnalyzer: extractRules with invalid rule entries ─────────────────
// Line 380: rules with missing id are skipped

test('rules without id are skipped gracefully', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - description: "no id here"
    effect: BLOCK
    condition:
      operations: [delete]
`;
  // Should not throw — just produce no logic diagnostics (structure validator handles missing id)
  expect(() => logicAnalyzer.analyze(yaml)).not.toThrow();
});

// ── RuleLogicAnalyzer: ESCALATE rules ────────────────────────────────────────

test('policy with only ESCALATE rules does not produce NO_ALLOW_RULE', () => {
  // checkMissingDefaultAllow only fires when hasAnyBlock AND !hasAnyAllow
  // A policy with only ESCALATE rules has no BLOCK — no warning
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: escalate-payments
    description: "escalate payments"
    effect: ESCALATE
    priority: 100
    condition:
      api_refs: [payments.api]
`;
  expect(codes(yaml, logicAnalyzer)).not.toContain('NO_ALLOW_RULE');
});

test('policy with ESCALATE and ALLOW does not produce NO_ALLOW_RULE', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: escalate-payments
    description: "escalate payments"
    effect: ESCALATE
    priority: 100
    condition:
      api_refs: [payments.api]
  - id: allow-reads
    description: "allow reads"
    effect: ALLOW
    priority: 900
    condition:
      operations: [read]
`;
  expect(codes(yaml, logicAnalyzer)).not.toContain('NO_ALLOW_RULE');
});

// ── YamlStructureValidator: INVALID_VERSION ───────────────────────────────────

test('version as an object produces INVALID_VERSION', () => {
  const yaml = `
name: test
version:
  major: 1
  minor: 0
rules: []
`;
  expect(codes(yaml, structureValidator)).toContain('INVALID_VERSION');
});

// ── YamlStructureValidator: RULE_INVALID_DESCRIPTION ─────────────────────────

test('empty description produces RULE_INVALID_DESCRIPTION', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: ""
    effect: BLOCK
    condition:
      operations: [delete]
`;
  expect(codes(yaml, structureValidator)).toContain('RULE_INVALID_DESCRIPTION');
});

// ── YamlStructureValidator: RULE_INVALID_PRIORITY ────────────────────────────

test('negative priority produces RULE_INVALID_PRIORITY', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    priority: -1
    condition:
      operations: [delete]
`;
  expect(codes(yaml, structureValidator)).toContain('RULE_INVALID_PRIORITY');
});

test('float priority produces RULE_INVALID_PRIORITY', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: r1
    description: "test"
    effect: BLOCK
    priority: 1.5
    condition:
      operations: [delete]
`;
  expect(codes(yaml, structureValidator)).toContain('RULE_INVALID_PRIORITY');
});
