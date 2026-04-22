/**
 * Tests for RuleLogicAnalyzer.
 * Each test mirrors a specific evaluation behaviour in srp/policy.py evaluate_policies().
 */

import * as vscode from 'vscode';
import { RuleLogicAnalyzer } from '../RuleLogicAnalyzer';

jest.mock('vscode', () => ({
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
}), { virtual: true });

const analyzer = new RuleLogicAnalyzer();

function codes(yaml: string) {
  return analyzer.analyze(yaml).map(d => d.code);
}

function warnings(yaml: string) {
  return analyzer.analyze(yaml).filter(d => d.severity === vscode.DiagnosticSeverity.Warning);
}

function errors(yaml: string) {
  return analyzer.analyze(yaml).filter(d => d.severity === vscode.DiagnosticSeverity.Error);
}

// ── 1. Duplicate IDs ──────────────────────────────────────────────────────────

test('duplicate rule IDs produce DUPLICATE_RULE_ID', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: my-rule
    description: "first"
    effect: BLOCK
    condition:
      operations: [delete]
  - id: my-rule
    description: "second"
    effect: ALLOW
    condition:
      operations: [read]
`;
  expect(codes(yaml)).toContain('DUPLICATE_RULE_ID');
});

test('unique IDs produce no DUPLICATE_RULE_ID', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: rule-a
    description: "a"
    effect: BLOCK
    condition:
      operations: [delete]
  - id: rule-b
    description: "b"
    effect: ALLOW
    condition:
      operations: [read]
`;
  expect(codes(yaml)).not.toContain('DUPLICATE_RULE_ID');
});

// ── 2. Priority conflicts ─────────────────────────────────────────────────────
// evaluate_policies() sorts by (priority, id) — same priority + overlapping = conflict

test('same priority with overlapping conditions produces PRIORITY_CONFLICT', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: rule-a
    description: "a"
    effect: BLOCK
    priority: 100
    condition:
      operations: [delete, drop]
  - id: rule-b
    description: "b"
    effect: ALLOW
    priority: 100
    condition:
      operations: [delete]
`;
  expect(codes(yaml)).toContain('PRIORITY_CONFLICT');
});

test('same priority with non-overlapping conditions is fine', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: rule-a
    description: "a"
    effect: BLOCK
    priority: 100
    condition:
      operations: [delete]
  - id: rule-b
    description: "b"
    effect: ALLOW
    priority: 100
    condition:
      operations: [read]
`;
  expect(codes(yaml)).not.toContain('PRIORITY_CONFLICT');
});

// ── 3. Empty conditions ───────────────────────────────────────────────────────
// _matches() returns True when all condition fields are None

test('BLOCK rule with empty condition produces EMPTY_CONDITION error', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: block-all
    description: "blocks everything"
    effect: BLOCK
    condition: {}
`;
  const errs = errors(yaml);
  expect(errs.map(d => d.code)).toContain('EMPTY_CONDITION');
});

test('ALLOW rule with empty condition produces EMPTY_CONDITION warning', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: allow-all
    description: "allows everything"
    effect: ALLOW
    condition: {}
`;
  const warns = warnings(yaml);
  expect(warns.map(d => d.code)).toContain('EMPTY_CONDITION');
});

// ── 4. Unreachable rules ──────────────────────────────────────────────────────
// evaluate_policies() returns on first match — a rule with a broader condition
// at lower priority number shadows a narrower rule at higher priority number

test('narrower rule after broader rule produces UNREACHABLE_RULE', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: broad-rule
    description: "matches all deletes"
    effect: BLOCK
    priority: 100
    condition:
      operations: [delete, drop, truncate]
  - id: narrow-rule
    description: "matches only delete"
    effect: ALLOW
    priority: 200
    condition:
      operations: [delete]
`;
  // narrow-rule's condition is a subset of broad-rule's — it's unreachable
  expect(codes(yaml)).toContain('UNREACHABLE_RULE');
});

test('non-overlapping rules are not unreachable', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: block-delete
    description: "block delete"
    effect: BLOCK
    priority: 100
    condition:
      operations: [delete]
  - id: allow-read
    description: "allow read"
    effect: ALLOW
    priority: 200
    condition:
      operations: [read]
`;
  expect(codes(yaml)).not.toContain('UNREACHABLE_RULE');
});

// ── 5. BLOCK shadowed by ALLOW ────────────────────────────────────────────────

test('BLOCK after ALLOW with overlapping conditions produces BLOCK_SHADOWED_BY_ALLOW', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: allow-reads
    description: "allow reads"
    effect: ALLOW
    priority: 100
    condition:
      operations: [read, list, get]
  - id: block-reads
    description: "block reads"
    effect: BLOCK
    priority: 200
    condition:
      operations: [read]
`;
  // allow-reads fires first for 'read' — block-reads never fires
  expect(codes(yaml)).toContain('BLOCK_SHADOWED_BY_ALLOW');
});

// ── 6. Missing default ALLOW ──────────────────────────────────────────────────

test('policy with only BLOCK rules produces NO_ALLOW_RULE information', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: block-delete
    description: "block delete"
    effect: BLOCK
    priority: 100
    condition:
      operations: [delete]
`;
  expect(codes(yaml)).toContain('NO_ALLOW_RULE');
});

test('policy with ALLOW rule does not produce NO_ALLOW_RULE', () => {
  const yaml = `
name: test
version: "1.0.0"
rules:
  - id: block-delete
    description: "block delete"
    effect: BLOCK
    priority: 100
    condition:
      operations: [delete]
  - id: allow-reads
    description: "allow reads"
    effect: ALLOW
    priority: 900
    condition:
      operations: [read]
`;
  expect(codes(yaml)).not.toContain('NO_ALLOW_RULE');
});
