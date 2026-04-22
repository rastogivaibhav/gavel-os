/**
 * RuleLogicAnalyzer.ts — Layer 2 validation.
 *
 * Catches logical errors that are structurally valid (Pydantic accepts them)
 * but operationally wrong. These are the silent bugs — the policy loads fine
 * but does not do what the author intended.
 *
 * All analysis mirrors the exact evaluation logic in:
 *   control-plane/srp/policy.py  evaluate_policies() and _matches()
 *
 * Checks:
 *   1. Duplicate rule IDs
 *   2. Priority conflicts (same priority, overlapping conditions)
 *   3. Empty conditions (matches every proposal)
 *   4. Unreachable rules (shadowed by a broader higher-priority rule)
 *   5. BLOCK shadowed by ALLOW at lower priority number
 *   6. Missing default ALLOW (all proposals may be blocked unintentionally)
 */

import * as vscode from 'vscode';
import * as yaml from 'js-yaml';
import { ValidationDiagnostic, ParsedRule } from './types';

export class RuleLogicAnalyzer {

  analyze(text: string): ValidationDiagnostic[] {
    const diagnostics: ValidationDiagnostic[] = [];
    let parsed: unknown;

    try {
      parsed = yaml.load(text);
    } catch {
      return []; // YamlStructureValidator already reported parse errors
    }

    if (typeof parsed !== 'object' || parsed === null) return [];
    const doc = parsed as Record<string, unknown>;
    if (!Array.isArray(doc.rules) || doc.rules.length === 0) return [];

    const rules = this.extractRules(doc.rules as unknown[], text);
    if (rules.length === 0) return [];

    this.checkDuplicateIds(rules, diagnostics);
    this.checkPriorityConflicts(rules, diagnostics);
    this.checkEmptyConditions(rules, diagnostics);
    this.checkUnreachableRules(rules, diagnostics);
    this.checkBlockShadowedByAllow(rules, diagnostics);
    this.checkMissingDefaultAllow(rules, diagnostics);

    return diagnostics;
  }

  // ── 1. Duplicate rule IDs ─────────────────────────────────────────────────
  // evaluate_policies() sorts by (priority, id). Two rules with the same id
  // produce non-deterministic ordering when priorities also match.
  private checkDuplicateIds(rules: ParsedRule[], diagnostics: ValidationDiagnostic[]): void {
    const seen = new Map<string, number>();
    for (const rule of rules) {
      if (seen.has(rule.id)) {
        diagnostics.push({
          message: `Duplicate rule ID '${rule.id}'. Rule IDs must be unique — evaluate_policies() sorts by (priority, id) and the first match wins.`,
          severity: vscode.DiagnosticSeverity.Error,
          line: rule.lineNumber,
          column: 0, endColumn: rule.id.length + 4,
          code: 'DUPLICATE_RULE_ID',
          ruleId: rule.id,
          fixData: { ruleId: rule.id, suggestedId: `${rule.id}-2` },
        });
      } else {
        seen.set(rule.id, rule.lineNumber);
      }
    }
  }

  // ── 2. Priority conflicts ─────────────────────────────────────────────────
  // Two rules with the same priority and overlapping conditions.
  // Tie-breaking is alphabetical by id — almost never intentional.
  private checkPriorityConflicts(rules: ParsedRule[], diagnostics: ValidationDiagnostic[]): void {
    const byPriority = new Map<number, ParsedRule[]>();
    for (const rule of rules) {
      const group = byPriority.get(rule.priority) ?? [];
      group.push(rule);
      byPriority.set(rule.priority, group);
    }

    for (const [priority, group] of byPriority) {
      if (group.length < 2) continue;
      for (let i = 0; i < group.length; i++) {
        for (let j = i + 1; j < group.length; j++) {
          if (this.conditionsOverlap(group[i].condition, group[j].condition)) {
            diagnostics.push({
              message: `Rules '${group[i].id}' and '${group[j].id}' share priority ${priority} with overlapping conditions. Tie-breaking is alphabetical by ID — set explicit priorities to make ordering deterministic.`,
              severity: vscode.DiagnosticSeverity.Warning,
              line: group[j].lineNumber,
              column: 0, endColumn: 8,
              code: 'PRIORITY_CONFLICT',
              ruleId: group[j].id,
              fixData: { ruleId: group[j].id, suggestedPriority: priority + 10 },
            });
          }
        }
      }
    }
  }

  // ── 3. Empty conditions ───────────────────────────────────────────────────
  // A rule with no condition fields matches EVERY proposal.
  // _matches() returns True when all condition fields are None.
  private checkEmptyConditions(rules: ParsedRule[], diagnostics: ValidationDiagnostic[]): void {
    for (const rule of rules) {
      const activeKeys = Object.keys(rule.condition).filter(
        k => rule.condition[k] !== null && rule.condition[k] !== undefined
      );

      if (activeKeys.length === 0) {
        const isBlock = rule.effect.toUpperCase() === 'BLOCK';
        diagnostics.push({
          message: `Rule '${rule.id}' has an empty condition — it matches EVERY proposal. ${
            isBlock
              ? 'This will BLOCK all agent actions regardless of caller, operation, or environment.'
              : 'Add at least one condition field to scope this rule.'
          }`,
          severity: isBlock
            ? vscode.DiagnosticSeverity.Error
            : vscode.DiagnosticSeverity.Warning,
          line: rule.lineNumber,
          column: 0, endColumn: rule.id.length + 4,
          code: 'EMPTY_CONDITION',
          ruleId: rule.id,
        });
      }
    }
  }

  // ── 4. Unreachable rules ──────────────────────────────────────────────────
  // evaluate_policies() returns on first match (sorted by priority, then id).
  // A rule is unreachable if a higher-priority rule with a superset condition
  // will always match first.
  private checkUnreachableRules(rules: ParsedRule[], diagnostics: ValidationDiagnostic[]): void {
    // Sort exactly as evaluate_policies() does
    const sorted = [...rules].sort((a, b) =>
      a.priority !== b.priority ? a.priority - b.priority : a.id.localeCompare(b.id)
    );

    for (let i = 0; i < sorted.length; i++) {
      for (let j = i + 1; j < sorted.length; j++) {
        // sorted[j] is evaluated after sorted[i]
        // If sorted[i]'s condition is a superset of sorted[j]'s, sorted[j] never fires
        if (this.conditionIsSubset(sorted[j].condition, sorted[i].condition)) {
          diagnostics.push({
            message: `Rule '${sorted[j].id}' (priority ${sorted[j].priority}) is unreachable — '${sorted[i].id}' (priority ${sorted[i].priority}) has a broader condition and always matches first.`,
            severity: vscode.DiagnosticSeverity.Warning,
            line: sorted[j].lineNumber,
            column: 0, endColumn: sorted[j].id.length + 4,
            code: 'UNREACHABLE_RULE',
            ruleId: sorted[j].id,
            fixData: {
              ruleId: sorted[j].id,
              shadowedBy: sorted[i].id,
              suggestedPriority: sorted[i].priority - 10,
            },
          });
        }
      }
    }
  }

  // ── 5. BLOCK shadowed by ALLOW ────────────────────────────────────────────
  // A BLOCK rule that is evaluated after an ALLOW rule with overlapping
  // conditions — the ALLOW fires first, the BLOCK never runs.
  private checkBlockShadowedByAllow(rules: ParsedRule[], diagnostics: ValidationDiagnostic[]): void {
    const sorted = [...rules].sort((a, b) =>
      a.priority !== b.priority ? a.priority - b.priority : a.id.localeCompare(b.id)
    );

    for (let i = 0; i < sorted.length; i++) {
      if (sorted[i].effect.toUpperCase() !== 'BLOCK') continue;
      for (let j = 0; j < i; j++) {
        if (
          sorted[j].effect.toUpperCase() === 'ALLOW' &&
          this.conditionsOverlap(sorted[i].condition, sorted[j].condition)
        ) {
          diagnostics.push({
            message: `BLOCK rule '${sorted[i].id}' (priority ${sorted[i].priority}) is shadowed by ALLOW rule '${sorted[j].id}' (priority ${sorted[j].priority}). The BLOCK will never fire for proposals matching both rules.`,
            severity: vscode.DiagnosticSeverity.Warning,
            line: sorted[i].lineNumber,
            column: 0, endColumn: sorted[i].id.length + 4,
            code: 'BLOCK_SHADOWED_BY_ALLOW',
            ruleId: sorted[i].id,
            fixData: {
              ruleId: sorted[i].id,
              shadowedBy: sorted[j].id,
              suggestedPriority: sorted[j].priority - 10,
            },
          });
        }
      }
    }
  }

  // ── 6. Missing default ALLOW ──────────────────────────────────────────────
  // If no rule matches, the VerdictEngine falls through to its built-in checks
  // (ENV_INVALID, REPLAY_NONCE_WEAK, API_NOT_ALLOWED, PARAM_TOO_LARGE).
  // A policy with only BLOCK rules and no ALLOW rule may be unintentionally
  // restrictive — warn the author.
  private checkMissingDefaultAllow(rules: ParsedRule[], diagnostics: ValidationDiagnostic[]): void {
    const hasAnyAllow = rules.some(r => r.effect.toUpperCase() === 'ALLOW');
    const hasAnyBlock = rules.some(r => r.effect.toUpperCase() === 'BLOCK');

    if (hasAnyBlock && !hasAnyAllow) {
      diagnostics.push({
        message: 'Policy has BLOCK rules but no ALLOW rules. Proposals that do not match any BLOCK rule fall through to VerdictEngine built-in checks — consider adding an explicit ALLOW rule for expected operations.',
        severity: vscode.DiagnosticSeverity.Information,
        line: 0, column: 0, endColumn: 5,
        code: 'NO_ALLOW_RULE',
      });
    }
  }

  // ── Condition overlap / subset helpers ────────────────────────────────────
  // These mirror the AND semantics of _matches() in srp/policy.py.
  // Two conditions overlap if there exists a proposal that matches both.
  // Condition A is a subset of B if every proposal matching A also matches B.

  private conditionsOverlap(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
    // Two conditions overlap if, for every list field present in both,
    // the lists share at least one value.
    for (const field of ['tenants', 'roles', 'environments', 'api_refs', 'operations']) {
      const aVal = a[field];
      const bVal = b[field];
      if (Array.isArray(aVal) && Array.isArray(bVal)) {
        const aSet = new Set(aVal as string[]);
        const hasCommon = (bVal as string[]).some(v => aSet.has(v));
        if (!hasCommon) return false;
      }
    }
    return true;
  }

  private conditionIsSubset(
    narrower: Record<string, unknown>,
    broader: Record<string, unknown>
  ): boolean {
    // broader is a superset of narrower if:
    // - For every list field in narrower, broader either has no constraint (null)
    //   or its list contains all values in narrower's list.
    for (const field of ['tenants', 'roles', 'environments', 'api_refs', 'operations']) {
      const narrowVal = narrower[field];
      const broadVal = broader[field];
      if (!Array.isArray(narrowVal)) continue;
      if (!Array.isArray(broadVal)) continue; // broader has no constraint → superset
      const broadSet = new Set(broadVal as string[]);
      const allCovered = (narrowVal as string[]).every(v => broadSet.has(v));
      if (!allCovered) return false;
    }
    return true;
  }

  // ── Rule extraction ───────────────────────────────────────────────────────

  private extractRules(rawRules: unknown[], text: string): ParsedRule[] {
    const lines = text.split('\n');
    const result: ParsedRule[] = [];

    for (const raw of rawRules) {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) continue;
      const r = raw as Record<string, unknown>;
      if (typeof r.id !== 'string') continue;

      const id = r.id;
      const effect = typeof r.effect === 'string' ? r.effect : 'ALLOW';
      const priority = typeof r.priority === 'number' ? r.priority : 1000;
      const condition = (typeof r.condition === 'object' && r.condition !== null && !Array.isArray(r.condition))
        ? r.condition as Record<string, unknown>
        : {};

      // Find the line where this rule's id appears
      let lineNumber = 0;
      for (let i = 0; i < lines.length; i++) {
        const t = lines[i].trimStart();
        if (t === `id: ${id}` || t === `id: '${id}'` || t === `id: "${id}"`) {
          lineNumber = i;
          break;
        }
      }

      result.push({ id, effect, priority, condition, lineNumber });
    }

    return result;
  }
}
