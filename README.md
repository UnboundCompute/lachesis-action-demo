# Lachesis Action — live demo

A working demo of the [**Lachesis Security Scan**](https://github.com/UnboundCompute/lachesis-action)
GitHub Action. Lachesis builds a compiler-precise code property graph, traces untrusted
input to dangerous sinks, and — its signature move — flags the endpoint that **forgot the
authorization check its sibling remembered**.

## What to look at

- **Pull requests** — each PR runs the Action and annotates the changed lines inline.
- **Security → Code scanning alerts** — the findings, ranked by severity.
- **The Actions tab** — the scan logs, and (for C) the candidate-registry census in the job summary.

## The signature finding: the guard differential

When two functions reach the same sink and one performs an authorization check while the
other does not, Lachesis reports the unchecked one as an **error** — not just "input reaches
a sink," but "*this* endpoint is missing the check its twin has."

```
public_exec(request)   →  os.system(cmd)                 UNGUARDED   error   ← the bug
admin_exec(request)    →  currentUser(); os.system(cmd)  GUARDED     note
relay_exec(request)    →  os.system(_relay(cmd))          UNGUARDED   error   ← interprocedural
```

Severity mapping:

| Level     | Meaning                                                            |
|-----------|-------------------------------------------------------------------|
| `error`   | Untrusted input reaches a sink **and** a guarded sibling exists — a missing-guard differential. |
| `warning` | Untrusted input reaches a sink with no guard (no sibling to compare against). |
| `note`    | The sink is reached but an authorization accessor is present.       |

## Languages

Examples live under `languages/`, one directory per language, each scanned in its own
matrix leg:

| Language | File                       | Fires via code scanning |
|----------|----------------------------|-------------------------|
| Python   | `languages/python/handlers.py` | ✅ (5 paths) |
| JavaScript | `languages/js/handlers.js`   | ✅ (3 paths) |
| TypeScript | `languages/ts/handlers.ts`   | ✅ (3 paths) |
| C        | `languages/c/handlers.c`       | ⚠️ see below |

Each language directory is scanned separately on purpose: a single mixed-language graph
currently stamps sinks for only one frontend, so per-directory legs are what make every
language's findings show up. Each leg uploads under its own code-scanning category so the
uploads don't overwrite one another.

## The C caveat

The C example contains real memory-safety bugs — a `strcpy` buffer overflow and an
unbounded `malloc`. The engine **does** detect them (in its candidate registry:
`memory.copy.capacity` and `memory.alloc.size`), but the Action's SARIF export currently
queries only the taint `security-paths` projection, which does not yet stamp C sources and
sinks. So today the C bugs **do not appear as code-scanning alerts** — the C matrix leg
prints the candidate census to the job summary instead. Bridging the candidate registry into
SARIF is the work that would light up C in code scanning.

## Using the Action in your own repo

```yaml
# .github/workflows/lachesis.yml
name: lachesis
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: UnboundCompute/lachesis-action@v1.0.1
        with:
          source: "."
          # fail-on: "error"   # fail the PR on guard differentials
```
