# Malformed and Incomplete Fixtures

## Scenarios
- `not-json.json`: Unparseable syntax. Must throw an explicit parsing error instead of silently passing as an empty diff.
- `missing-lockfile-version.json`: Missing `lockfileVersion`. Flagged as malformed/incomplete.
- `unsupported-version-v2.json`: Lockfile version 2. The MVP supports lockfile v3 exclusively; earlier versions must be rejected with an explicit incomplete/unsupported outcome.
- `unsupported-source-git.json`: Contains a `git+https://` dependency. The comparator flags this as `unsupported: true` with reason `"GIT_DEPENDENCY_UNSUPPORTED"`.
