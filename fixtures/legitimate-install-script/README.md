# Legitimate Install Script Fixture

## Scenario
- **Base**: Standard app (`picocolors@1.1.1`).
- **Head**: Adds `mock-native-binding@1.0.0` with `hasInstallScript: true`.
- **Purpose**:
  - Tests false-positive reviewability.
  - A legitimate build script (e.g. `node-gyp rebuild` or standard platform binary download) should be flagged for review (`QUARANTINE` initially) with clear observations, but NOT automatically branded as malicious malware.
  - Demonstrates that a human reviewer can inspect the cited evidence and approve (`ALLOW`) with a documented rationale.
