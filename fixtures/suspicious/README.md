# Suspicious Lifecycle Script Fixture

## Scenario
- **Base**: Standard benign app (`picocolors@1.1.1`).
- **Head**: Introduces `mock-telemetry-reporter@1.0.0`, declaring an install script (`hasInstallScript: true`).
- **Static Detection Triggers**:
  - `LIFECYCLE_SCRIPT_ADDED`: New lifecycle script introduced in candidate.
  - In Phase 2: Static AST/token scan flags environment variable access and outbound HTTP connection markers.
- **Expected Outcome**:
  - Automatically held under `QUARANTINE`.
  - Gate exits with code 2 (QUARANTINE) unless an explicit human override decision is recorded.
