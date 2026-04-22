/**
 * Minimal vscode mock for Jest.
 * Only the APIs used by the validation layer need to be mocked.
 */

export enum DiagnosticSeverity {
  Error = 0,
  Warning = 1,
  Information = 2,
  Hint = 3,
}

export class Position {
  constructor(public line: number, public character: number) {}
}

export class Range {
  constructor(public start: Position, public end: Position) {}
}

export class Diagnostic {
  constructor(
    public range: Range,
    public message: string,
    public severity: DiagnosticSeverity
  ) {}
  code?: string;
  source?: string;
}

export class ThemeColor {
  constructor(public id: string) {}
}

export class ThemeIcon {
  constructor(public id: string, public color?: ThemeColor) {}
}

export class Uri {
  static parse(value: string) { return { fsPath: value, toString: () => value }; }
  static joinPath(...args: unknown[]) { return args[0]; }
}

export class EventEmitter<T> {
  event = (_listener: (e: T) => void) => ({ dispose: () => {} });
  fire(_event: T) {}
  dispose() {}
}

export const workspace = {
  getConfiguration: () => ({
    get: (key: string, def: unknown) => def,
  }),
  textDocuments: [],
  onDidSaveTextDocument: () => ({ dispose: () => {} }),
  onDidOpenTextDocument: () => ({ dispose: () => {} }),
  onDidCloseTextDocument: () => ({ dispose: () => {} }),
  onDidChangeConfiguration: () => ({ dispose: () => {} }),
  registerTextDocumentContentProvider: () => ({ dispose: () => {} }),
};

export const window = {
  createStatusBarItem: () => ({
    show: () => {}, hide: () => {}, dispose: () => {},
    text: '', tooltip: '', backgroundColor: undefined, command: '',
  }),
  createTreeView: () => ({ dispose: () => {} }),
  createTerminal: () => ({ show: () => {}, sendText: () => {} }),
  showInformationMessage: () => Promise.resolve(),
  showWarningMessage: () => Promise.resolve(),
  showErrorMessage: () => Promise.resolve(),
  showQuickPick: () => Promise.resolve(undefined),
  activeTextEditor: undefined,
};

export const languages = {
  createDiagnosticCollection: () => ({
    set: () => {}, delete: () => {}, dispose: () => {},
  }),
  registerCodeActionsProvider: () => ({ dispose: () => {} }),
};

export const commands = {
  registerCommand: () => ({ dispose: () => {} }),
};

export const env = {
  clipboard: { writeText: () => Promise.resolve() },
};

export const StatusBarAlignment = { Left: 1, Right: 2 };
export const ViewColumn = { One: 1, Two: 2, Beside: -2 };
export const CodeActionKind = {
  QuickFix: { value: 'quickfix', append: (s: string) => ({ value: s }) },
};

export class CodeAction {
  constructor(public title: string, public kind: unknown) {}
  diagnostics?: Diagnostic[];
  edit?: WorkspaceEdit;
}

export class WorkspaceEdit {
  replace() {}
  insert() {}
  delete() {}
}

export class MarkdownString {
  constructor(public value: string) {}
}
