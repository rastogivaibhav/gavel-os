/**
 * YamlStructureValidator.ts — Layer 1 validation.
 *
 * Mirrors every constraint from the Pydantic models in the control plane:
 *   PolicySet      → control-plane/srp/policy.py  PolicySet
 *   PolicyRule     → control-plane/srp/policy.py  PolicyRule
 *   PolicyCondition→ control-plane/srp/policy.py  PolicyCondition
 *   environments   → control-plane/srp/models.py  Literal["dev","staging","prod"]
 *
 * Runs entirely in the extension host — no network call required.
 * Catches every error that would cause Pydantic to reject the file at runtime.
 */

import * as vscode from 'vscode';
import * as yaml from 'js-yaml';
import { ValidationDiagnostic } from './types';

// ── Mirrors PolicyEffect enum in srp/policy.py ────────────────────────────────
const VALID_EFFECTS = new Set(['ALLOW', 'BLOCK', 'ESCALATE']);

// ── Mirrors Literal["dev","staging","prod"] in srp/models.py ─────────────────
const VALID_ENVIRONMENTS = new Set(['dev', 'staging', 'prod']);

// ── Mirrors PolicyCondition field names in srp/policy.py ─────────────────────
const VALID_CONDITION_KEYS = new Set([
  'tenants', 'roles', 'environments', 'api_refs',
  'operations', 'max_numeric_parameters',
]);

// ── Required fields on PolicyRule ─────────────────────────────────────────────
const REQUIRED_RULE_FIELDS = ['id', 'description', 'effect', 'condition'];

// ── Required fields on PolicySet ──────────────────────────────────────────────
const REQUIRED_TOP_LEVEL = ['name', 'version', 'rules'];

export class YamlStructureValidator {

  validate(text: string): ValidationDiagnostic[] {
    const diagnostics: ValidationDiagnostic[] = [];

    // ── Parse YAML ────────────────────────────────────────────────────────────
    let parsed: unknown;
    try {
      parsed = yaml.load(text);
    } catch (e: unknown) {
      const err = e as yaml.YAMLException;
      diagnostics.push({
        message: `YAML parse error: ${err.reason ?? String(err)}`,
        severity: vscode.DiagnosticSeverity.Error,
        line: err.mark?.line ?? 0,
        column: err.mark?.column ?? 0,
        endColumn: (err.mark?.column ?? 0) + 1,
        code: 'YAML_PARSE_ERROR',
      });
      return diagnostics;
    }

    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      diagnostics.push({
        message: 'Policy file must be a YAML mapping at the top level',
        severity: vscode.DiagnosticSeverity.Error,
        line: 0, column: 0, endColumn: 1,
        code: 'NOT_A_MAPPING',
      });
      return diagnostics;
    }

    const doc = parsed as Record<string, unknown>;

    // ── Top-level required fields ─────────────────────────────────────────────
    for (const field of REQUIRED_TOP_LEVEL) {
      if (!(field in doc)) {
        const line = this.findKeyLine(text, field) ?? 0;
        diagnostics.push({
          message: `Missing required field: '${field}'`,
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: field.length,
          code: 'MISSING_REQUIRED_FIELD',
          fixData: { field },
        });
      }
    }

    // ── name: non-empty string (mirrors constr(min_length=1)) ─────────────────
    if ('name' in doc) {
      if (typeof doc.name !== 'string' || doc.name.trim().length === 0) {
        const line = this.findKeyLine(text, 'name') ?? 0;
        diagnostics.push({
          message: "'name' must be a non-empty string",
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: 4,
          code: 'INVALID_NAME',
        });
      }
    }

    // ── version: string or number (YamlPolicyLoader calls str(data["version"])) ─
    if ('version' in doc) {
      if (typeof doc.version !== 'string' && typeof doc.version !== 'number') {
        const line = this.findKeyLine(text, 'version') ?? 0;
        diagnostics.push({
          message: "'version' must be a string (e.g. \"1.0.0\")",
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: 7,
          code: 'INVALID_VERSION',
        });
      }
    }

    // ── rules: non-empty array ────────────────────────────────────────────────
    if ('rules' in doc) {
      if (!Array.isArray(doc.rules)) {
        const line = this.findKeyLine(text, 'rules') ?? 0;
        diagnostics.push({
          message: "'rules' must be a list",
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: 5,
          code: 'RULES_NOT_ARRAY',
        });
      } else if (doc.rules.length === 0) {
        const line = this.findKeyLine(text, 'rules') ?? 0;
        diagnostics.push({
          message: 'Policy has no rules — all proposals fall through to VerdictEngine built-in checks only',
          severity: vscode.DiagnosticSeverity.Warning,
          line, column: 0, endColumn: 5,
          code: 'EMPTY_RULES',
        });
      } else {
        for (const [i, rule] of (doc.rules as unknown[]).entries()) {
          this.validateRule(rule, i, text, diagnostics);
        }
      }
    }

    return diagnostics;
  }

  private validateRule(
    rule: unknown,
    index: number,
    text: string,
    diagnostics: ValidationDiagnostic[]
  ): void {
    if (typeof rule !== 'object' || rule === null || Array.isArray(rule)) {
      diagnostics.push({
        message: `Rule at index ${index} must be a mapping`,
        severity: vscode.DiagnosticSeverity.Error,
        line: 0, column: 0, endColumn: 1,
        code: 'RULE_NOT_MAPPING',
      });
      return;
    }

    const r = rule as Record<string, unknown>;
    const ruleId = typeof r.id === 'string' ? r.id : `rule[${index}]`;

    // ── Required fields ───────────────────────────────────────────────────────
    for (const field of REQUIRED_RULE_FIELDS) {
      if (!(field in r)) {
        const line = this.findRuleFieldLine(text, ruleId, field) ?? 0;
        diagnostics.push({
          message: `Rule '${ruleId}': missing required field '${field}'`,
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: field.length,
          code: 'RULE_MISSING_FIELD',
          ruleId,
          fixData: { ruleId, field },
        });
      }
    }

    // ── id: non-empty string ──────────────────────────────────────────────────
    if ('id' in r && (typeof r.id !== 'string' || (r.id as string).trim().length === 0)) {
      const line = this.findRuleFieldLine(text, ruleId, 'id') ?? 0;
      diagnostics.push({
        message: `Rule at index ${index}: 'id' must be a non-empty string`,
        severity: vscode.DiagnosticSeverity.Error,
        line, column: 0, endColumn: 2,
        code: 'RULE_INVALID_ID',
        ruleId,
      });
    }

    // ── description: non-empty string ────────────────────────────────────────
    if ('description' in r && (typeof r.description !== 'string' || (r.description as string).trim().length === 0)) {
      const line = this.findRuleFieldLine(text, ruleId, 'description') ?? 0;
      diagnostics.push({
        message: `Rule '${ruleId}': 'description' must be a non-empty string`,
        severity: vscode.DiagnosticSeverity.Error,
        line, column: 0, endColumn: 11,
        code: 'RULE_INVALID_DESCRIPTION',
        ruleId,
      });
    }

    // ── effect: ALLOW | BLOCK | ESCALATE ─────────────────────────────────────
    // Mirrors PolicyEffect enum — YamlPolicyLoader calls .upper() so case-insensitive
    if ('effect' in r) {
      const effectNorm = typeof r.effect === 'string' ? r.effect.toUpperCase() : '';
      if (!VALID_EFFECTS.has(effectNorm)) {
        const line = this.findRuleFieldLine(text, ruleId, 'effect') ?? 0;
        diagnostics.push({
          message: `Rule '${ruleId}': invalid effect '${r.effect}'. Must be ALLOW, BLOCK, or ESCALATE`,
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: 6,
          code: 'RULE_INVALID_EFFECT',
          ruleId,
          fixData: { ruleId, currentEffect: r.effect },
        });
      }
    }

    // ── priority: non-negative integer ───────────────────────────────────────
    if ('priority' in r) {
      if (typeof r.priority !== 'number' || !Number.isInteger(r.priority) || r.priority < 0) {
        const line = this.findRuleFieldLine(text, ruleId, 'priority') ?? 0;
        diagnostics.push({
          message: `Rule '${ruleId}': 'priority' must be a non-negative integer`,
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: 8,
          code: 'RULE_INVALID_PRIORITY',
          ruleId,
        });
      }
    }

    // ── condition ─────────────────────────────────────────────────────────────
    if ('condition' in r) {
      this.validateCondition(r.condition, ruleId, text, diagnostics);
    }
  }

  private validateCondition(
    condition: unknown,
    ruleId: string,
    text: string,
    diagnostics: ValidationDiagnostic[]
  ): void {
    if (typeof condition !== 'object' || condition === null || Array.isArray(condition)) {
      diagnostics.push({
        message: `Rule '${ruleId}': 'condition' must be a mapping`,
        severity: vscode.DiagnosticSeverity.Error,
        line: 0, column: 0, endColumn: 9,
        code: 'CONDITION_NOT_MAPPING',
        ruleId,
      });
      return;
    }

    const cond = condition as Record<string, unknown>;

    // ── Unknown keys (PolicyCondition has no extra="forbid" but unknown keys are silently ignored) ──
    // We warn rather than error — the server ignores them but they indicate a typo
    for (const key of Object.keys(cond)) {
      if (!VALID_CONDITION_KEYS.has(key)) {
        const line = this.findRuleFieldLine(text, ruleId, key) ?? 0;
        diagnostics.push({
          message: `Rule '${ruleId}': unknown condition field '${key}'. Valid fields: ${[...VALID_CONDITION_KEYS].join(', ')}`,
          severity: vscode.DiagnosticSeverity.Warning,
          line, column: 0, endColumn: key.length,
          code: 'CONDITION_UNKNOWN_KEY',
          ruleId,
          fixData: { ruleId, unknownKey: key },
        });
      }
    }

    // ── List fields: conlist(constr(min_length=1), min_length=1) ──────────────
    for (const listField of ['tenants', 'roles', 'api_refs', 'operations']) {
      if (!(listField in cond)) continue;
      const val = cond[listField];

      if (!Array.isArray(val)) {
        const line = this.findRuleFieldLine(text, ruleId, listField) ?? 0;
        diagnostics.push({
          message: `Rule '${ruleId}': condition.${listField} must be a list`,
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: listField.length,
          code: 'CONDITION_FIELD_NOT_ARRAY',
          ruleId,
        });
        continue;
      }

      // conlist min_length=1
      if (val.length === 0) {
        const line = this.findRuleFieldLine(text, ruleId, listField) ?? 0;
        diagnostics.push({
          message: `Rule '${ruleId}': condition.${listField} must have at least one item (Pydantic conlist min_length=1)`,
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: listField.length,
          code: 'CONDITION_EMPTY_LIST',
          ruleId,
        });
        continue;
      }

      // constr(strip_whitespace=True, min_length=1) on each item
      for (const [i, item] of val.entries()) {
        if (typeof item !== 'string' || (item as string).trim().length === 0) {
          const line = this.findRuleFieldLine(text, ruleId, listField) ?? 0;
          diagnostics.push({
            message: `Rule '${ruleId}': condition.${listField}[${i}] must be a non-empty string`,
            severity: vscode.DiagnosticSeverity.Error,
            line, column: 0, endColumn: listField.length,
            code: 'CONDITION_EMPTY_STRING_ITEM',
            ruleId,
          });
        }
      }
    }

    // ── environments: values must be dev | staging | prod ────────────────────
    // Mirrors Literal["dev","staging","prod"] in srp/models.py
    if ('environments' in cond && Array.isArray(cond.environments)) {
      for (const env of cond.environments as unknown[]) {
        if (!VALID_ENVIRONMENTS.has(env as string)) {
          const line = this.findRuleFieldLine(text, ruleId, 'environments') ?? 0;
          diagnostics.push({
            message: `Rule '${ruleId}': invalid environment '${env}'. Must be dev, staging, or prod`,
            severity: vscode.DiagnosticSeverity.Error,
            line, column: 0, endColumn: 12,
            code: 'CONDITION_INVALID_ENVIRONMENT',
            ruleId,
            fixData: { ruleId, invalidEnv: env },
          });
        }
      }
    }

    // ── max_numeric_parameters: Dict[str, float] ──────────────────────────────
    if ('max_numeric_parameters' in cond) {
      const mnp = cond.max_numeric_parameters;
      if (typeof mnp !== 'object' || mnp === null || Array.isArray(mnp)) {
        const line = this.findRuleFieldLine(text, ruleId, 'max_numeric_parameters') ?? 0;
        diagnostics.push({
          message: `Rule '${ruleId}': max_numeric_parameters must be a mapping of field names to numbers`,
          severity: vscode.DiagnosticSeverity.Error,
          line, column: 0, endColumn: 22,
          code: 'CONDITION_INVALID_MAX_NUMERIC',
          ruleId,
        });
      } else {
        for (const [k, v] of Object.entries(mnp as Record<string, unknown>)) {
          if (typeof v !== 'number') {
            const line = this.findRuleFieldLine(text, ruleId, k) ?? 0;
            diagnostics.push({
              message: `Rule '${ruleId}': max_numeric_parameters.${k} must be a number, got ${typeof v}`,
              severity: vscode.DiagnosticSeverity.Error,
              line, column: 0, endColumn: k.length,
              code: 'CONDITION_MAX_NUMERIC_NOT_NUMBER',
              ruleId,
            });
          }
        }
      }
    }
  }

  // ── Line-finding helpers ──────────────────────────────────────────────────

  private findKeyLine(text: string, key: string): number | undefined {
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trimStart().startsWith(`${key}:`)) return i;
    }
    return undefined;
  }

  private findRuleFieldLine(text: string, ruleId: string, field: string): number | undefined {
    const lines = text.split('\n');
    let inRule = false;
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trimStart();
      if (trimmed === `id: ${ruleId}` || trimmed === `id: '${ruleId}'` || trimmed === `id: "${ruleId}"`) {
        inRule = true;
      }
      if (inRule && trimmed.startsWith(`${field}:`)) return i;
      if (inRule && i > 0 && trimmed.startsWith('- id:') && !trimmed.includes(ruleId)) {
        inRule = false;
      }
    }
    return undefined;
  }
}
