import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

describe('Schema Contracts Validation', () => {
  it('validates evidence.schema.json structure', async () => {
    const raw = await readFile(resolve('schemas/evidence.schema.json'), 'utf8');
    const schema = JSON.parse(raw);

    assert.equal(schema.title, 'EvidenceBundle');
    assert.ok(schema.required.includes('subjectDigest'));
    assert.ok(schema.required.includes('packages'));
    assert.ok(schema.properties.packages.items.required.includes('isDirect'));
  });

  it('validates investigation.schema.json structure', async () => {
    const raw = await readFile(resolve('schemas/investigation.schema.json'), 'utf8');
    const schema = JSON.parse(raw);

    assert.equal(schema.title, 'InvestigationOutput');
    assert.ok(schema.required.includes('role'));
    assert.ok(schema.required.includes('findings'));
    assert.deepEqual(schema.properties.role.enum, [
      'typosquat-detective',
      'provenance-auditor',
      'behavior-analyst'
    ]);
  });

  it('validates decision.schema.json structure', async () => {
    const raw = await readFile(resolve('schemas/decision.schema.json'), 'utf8');
    const schema = JSON.parse(raw);

    assert.equal(schema.title, 'DecisionEnvelope');
    assert.ok(schema.required.includes('mode'));
    assert.ok(schema.required.includes('subjectDigest'));
    assert.deepEqual(schema.properties.mode.enum, ['trusted-local-demo', 'signed-local']);
  });
});
