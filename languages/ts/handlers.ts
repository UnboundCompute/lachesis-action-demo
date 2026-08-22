// TypeScript request handlers — command injection with a guard differential.
//
// Same shape as the JS example, through the TypeScript frontend: untrusted
// web-input reaches child_process.exec, one route guarded and one not.

import { exec } from "child_process";

interface Request {
  param(name: string): string;
  get(header: string): string;
}

// Authorization accessor. Its presence marks a handler 'guarded'.
export function currentUser(req: Request): string {
  return req.get("X-User");
}

// Pass-through helper: carries taint across a call boundary unchanged.
export function relay(value: string): string {
  return value;
}

// UNGUARDED. Untrusted web-input -> exec, no authorization accessor.
// Differential sibling of adminReport -> error.
export function runReport(req: Request): void {
  const id = req.param("cmd");
  exec(id);
}

// GUARDED. Same flow, currentUser() present -> note.
export function adminReport(req: Request): void {
  currentUser(req);
  const id = req.param("cmd");
  exec(id);
}

// INTERPROCEDURAL. Taint crosses relay() before the sink -> warning.
export function relayReport(req: Request): void {
  const id = req.param("cmd");
  exec(relay(id));
}
