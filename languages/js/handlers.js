// JavaScript request handlers — command injection with a guard differential.
//
// Untrusted request input reaches child_process.exec. One route performs an
// authorization check (currentUser) before the sink; its sibling does not.
// Handlers are exported so the analyzer's prune pass keeps them as entry points.

const { exec } = require("child_process");

// Authorization accessor. Its presence marks a handler 'guarded'.
function currentUser(req) {
  return req.get("X-User");
}

// Pass-through helper: carries taint across a call boundary unchanged.
function relay(value) {
  return value;
}

// UNGUARDED. req.param() is untrusted web-input; it flows straight into exec
// with no authorization accessor. Differential sibling of adminReport -> error.
function runReport(req) {
  const id = req.param("cmd");
  exec(id);
}

// GUARDED. Same web-input -> exec flow, but currentUser() is present -> note.
function adminReport(req) {
  currentUser(req);
  const id = req.param("cmd");
  exec(id);
}

// INTERPROCEDURAL. Taint crosses relay() before reaching exec -> warning.
function relayReport(req) {
  const id = req.param("cmd");
  exec(relay(id));
}

module.exports = { currentUser, runReport, adminReport, relayReport };
