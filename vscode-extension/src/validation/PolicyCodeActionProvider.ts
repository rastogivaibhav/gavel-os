/**
 * PolicyCodeActionProvider.ts — Auto-fix suggestions for policy diagnostics.
 *
 * Each diagnostic code maps to a specific fix action.
 * The fixData field on ValidationDiagnostic carries the structured data
 * needed to generate the edit.
 */

import * as vscode from 'vscode';

export class PolicyCodeActionProvider implements vscode.CodeActionProvider {

  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== 'gavel') continue;

      switch (diagnostic.code) {

        // ── Fix: add missing required field ────────────────────────────────
        case 'MISSING_REQUIRED_FIELD': {
          const fix = this.createFix(
            document,
            diagnostic,
            `Add missing field '${this.getFixField(diagnostic)}'`,
            this.insertionForMissingField(document, diagnostic)
          );
          if (fix) actions.push(fix);
          break;
        }

        // ── Fix: correct invalid effect ────────────────────────────────────
        case 'RULE_INVALID_EFFECT': {
          for (const effect of ['ALLOW', 'BLOCK', 'ESCALATE']) {
            const fix = new vscode.CodeAction(
              `Change effect to '${effect}'`,
              vscode.CodeActionKind.QuickFix
            );
            fix.diagnostics = [diagnostic];
            fix.edit = new vscode.WorkspaceEdit();
            fix.edit.replace(document.uri, diagnostic.range, `effect: ${effect}`);
            actions.push(fix);
          }
          break;
        }

        // ── Fix: correct invalid environment ──────────────────────────────
        case 'CONDITION_INVALID_ENVIRONMENT': {
          for (const env of ['dev', 'staging', 'prod']) {
            const fix = new vscode.CodeAction(
              `Change to '${env}'`,
              vscode.CodeActionKind.QuickFix
            );
            fix.diagnostics = [diagnostic];
            fix.edit = new vscode.WorkspaceEdit();
            fix.edit.replace(document.uri, diagnostic.range, `- ${env}`);
            actions.push(fix);
          }
          break;
        }

        // ── Fix: rename duplicate rule ID ──────────────────────────────────
        case 'DUPLICATE_RULE_ID': {
          const line = document.lineAt(diagnostic.range.start.line);
          const currentId = line.text.trim().replace('id: ', '').replace(/['"]/g, '');
          const suggestedId = `${currentId}-${Date.now().toString(36)}`;
          const fix = new vscode.CodeAction(
            `Rename to '${suggestedId}'`,
            vscode.CodeActionKind.QuickFix
          );
          fix.diagnostics = [diagnostic];
          fix.edit = new vscode.WorkspaceEdit();
          fix.edit.replace(document.uri, diagnostic.range, `id: ${suggestedId}`);
          actions.push(fix);
          break;
        }

        // ── Fix: adjust priority to resolve conflict ───────────────────────
        case 'PRIORITY_CONFLICT':
        case 'UNREACHABLE_RULE':
        case 'BLOCK_SHADOWED_BY_ALLOW': {
          const line = document.lineAt(diagnostic.range.start.line);
          const priorityMatch = document.getText().match(/priority:\s*(\d+)/);
          if (priorityMatch) {
            const current = parseInt(priorityMatch[1], 10);
            const suggested = current - 10;
            const fix = new vscode.CodeAction(
              `Change priority to ${suggested} (move earlier in evaluation order)`,
              vscode.CodeActionKind.QuickFix
            );
            fix.diagnostics = [diagnostic];
            // Find the priority line for this rule and replace it
            const text = document.getText();
            const ruleId = diagnostic.code === 'PRIORITY_CONFLICT'
              ? line.text.trim()
              : '';
            const priorityLineIdx = this.findPriorityLineForRule(text, ruleId, diagnostic.range.start.line);
            if (priorityLineIdx >= 0) {
              const priorityLine = document.lineAt(priorityLineIdx);
              fix.edit = new vscode.WorkspaceEdit();
              fix.edit.replace(
                document.uri,
                priorityLine.range,
                priorityLine.text.replace(/priority:\s*\d+/, `priority: ${suggested}`)
              );
              actions.push(fix);
            }
          }
          break;
        }

        // ── Fix: remove unknown condition key ──────────────────────────────
        case 'CONDITION_UNKNOWN_KEY': {
          const fix = new vscode.CodeAction(
            'Remove unknown condition field',
            vscode.CodeActionKind.QuickFix
          );
          fix.diagnostics = [diagnostic];
          fix.edit = new vscode.WorkspaceEdit();
          // Delete the entire line containing the unknown key
          const lineRange = document.lineAt(diagnostic.range.start.line).rangeIncludingLineBreak;
          fix.edit.delete(document.uri, lineRange);
          actions.push(fix);
          break;
        }
      }
    }

    return actions;
  }

  private createFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    title: string,
    edit: vscode.WorkspaceEdit | null
  ): vscode.CodeAction | null {
    if (!edit) return null;
    const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
    action.diagnostics = [diagnostic];
    action.edit = edit;
    return action;
  }

  private getFixField(diagnostic: vscode.Diagnostic): string {
    // The field name is embedded in the diagnostic message
    const match = diagnostic.message.match(/Missing required field: '(\w+)'/);
    return match?.[1] ?? 'unknown';
  }

  private insertionForMissingField(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.WorkspaceEdit | null {
    const field = this.getFixField(diagnostic);
    const placeholders: Record<string, string> = {
      name: 'name: my-policy',
      version: 'version: "1.0.0"',
      rules: 'rules: []',
      id: '  id: my-rule',
      description: '  description: "Describe what this rule does"',
      effect: '  effect: BLOCK',
      condition: '  condition: {}',
    };
    const snippet = placeholders[field];
    if (!snippet) return null;

    const edit = new vscode.WorkspaceEdit();
    const insertPos = new vscode.Position(diagnostic.range.start.line, 0);
    edit.insert(document.uri, insertPos, snippet + '\n');
    return edit;
  }

  private findPriorityLineForRule(text: string, _ruleId: string, nearLine: number): number {
    const lines = text.split('\n');
    // Search within 10 lines of the diagnostic for a priority: field
    for (let i = nearLine; i < Math.min(nearLine + 10, lines.length); i++) {
      if (lines[i].trimStart().startsWith('priority:')) return i;
    }
    return -1;
  }
}
