/**
 * Shared types for the policy validation pipeline.
 */

import * as vscode from 'vscode';

export interface ValidationDiagnostic {
  /** Human-readable message shown in the Problems panel */
  message: string;
  severity: vscode.DiagnosticSeverity;
  /** 0-indexed line number */
  line: number;
  column: number;
  endColumn: number;
  /** Machine-readable code used by PolicyCodeActionProvider to offer fixes */
  code: string;
  /** Which rule triggered this diagnostic, if applicable */
  ruleId?: string;
  /** Structured data the CodeActionProvider uses to generate a fix */
  fixData?: unknown;
}

/** A parsed rule extracted from the YAML for logic analysis */
export interface ParsedRule {
  id: string;
  effect: string;
  priority: number;
  condition: Record<string, unknown>;
  /** 0-indexed line where this rule's `- id:` appears */
  lineNumber: number;
}
