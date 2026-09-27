# Benign Addition & Version Bump Fixture

## Scenario
- **Base**: Contains `ms@2.1.2`.
- **Head**: Updates `ms` to `2.1.3` (semver patch) and adds direct dependency `picocolors@1.1.1`.
- **Expected Outcome**:
  - `ms`: `changeType: "changed"`, `isDirect: true`
  - `picocolors`: `changeType: "added"`, `isDirect: true`
  - Zero lifecycle scripts, valid SRI hashes, zero policy violations.
  - Expected gate verdict: `ALLOW` once reviewed.
