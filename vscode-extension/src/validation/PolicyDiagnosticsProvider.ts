/**
 * PolicyDiagnosticsProvider.ts — Wires all validation layers together.
 *
 * Runs on every file save (if gavel.validateOnSave is true) and on-demand
 * via the "Gavel: Validate Policy File" command.
 *
 * Validation pipeline:
 *   1. YamlStructureValidator — Pydantic-equivalent checks
 *   2. RuleLogicAnalyzer      — logical errors (duplicates, conflicts, unreachable)
 *   3. (Future) CrossFileConsistencyChecker — YAML ops vs data.json
 *   4. (Future) LiveValidationClient — POST /external/validate with synthetic proposal
 */

import * as vscode from 'vscode';
import { YamlStructureValidator } from './YamlStructureValidator';
import { RuleLogicAnalyzer } from './RuleLogicAnalyzer';
import { ValidationDiagnostic } from './types';

export class PolicyDiagnosticsProvider {
  private readonly diagnostics: vscode.DiagnosticCollection;
  private readonly structureValidator = new YamlStructureValidator();
  private readonly logicAnalyzer = new RuleLogicAnalyzer();

  constructor() {
    this.diagnostics = vscode.languages.createDiagnosticCollection('gavel-policy');
  }

  /**
   * Validate a policy YAML file and publish diagnostics to the Problems panel.
   * Returns true if validation passed (no errors), false otherwise.
   */
  validate(document: vscode.TextDocument): boolean {
    if (!this.isPolicyFile(document)) {
      return true;
    }

    const text = document.getText();
    const allDiagnostics: ValidationDiagnostic[] = [];

    // Layer 1: structure
    const structureErrors = this.structureValidator.validate(text);
    allDiagnostics.push(...structureErrors);

    // Layer 2: logic (only if structure is valid — no point analyzing broken YAML)
    const hasStructureErrors = structureErrors.some(
      d => d.severity === vscode.DiagnosticSeverity.Error
    );
    if (!hasStructureErrors) {
      const logicWarnings = this.logicAnalyzer.analyze(text);
      allDiagnostics.push(...logicWarnings);
    }

    // Convert to VS Code Diagnostic objects
    const vsDiagnostics = allDiagnostics.map(d => {
      const range = new vscode.Range(
        new vscode.Position(d.line, d.column),
        new vscode.Position(d.line, d.endColumn)
      );
      const diag = new vscode.Diagnostic(range, d.message, d.severity);
      diag.code = d.code;
      diag.source = 'gavel';
      return diag;
    });

    this.diagnostics.set(document.uri, vsDiagnostics);

    const hasErrors = vsDiagnostics.some(d => d.severity === vscode.DiagnosticSeverity.Error);
    return !hasErrors;
  }

  /**
   * Clear diagnostics for a document (called when the file is closed).
   */
  clear(document: vscode.TextDocument): void {
    this.diagnostics.delete(document.uri);
  }

  /**
   * Check if a document is a Gavel policy file.
   * Heuristic: path contains /policies/ and extension is .yaml or .yml
   */
  private isPolicyFile(document: vscode.TextDocument): boolean {
    const path = document.uri.fsPath;
    return (
      (path.includes('/policies/') || path.includes('\\policies\\')) &&
      (document.languageId === 'yaml' || path.endsWith('.yaml') || path.endsWith('.yml'))
    );
  }

  dispose(): void {
    this.diagnostics.dispose();
  }
}
