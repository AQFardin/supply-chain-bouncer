import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

/**
 * Recursive pure Node.js JSON schema validator supporting type, enum, pattern, required,
 * properties, items, and strict additionalProperties: false.
 */
export function validateAgainstSchema(schema, data, path = '$') {
  if (schema.type) {
    const allowedTypes = Array.isArray(schema.type) ? schema.type : [schema.type];
    const isInt = typeof data === 'number' && Number.isInteger(data);
    const actualType = data === null ? 'null' : Array.isArray(data) ? 'array' : typeof data;
    const typeMatches = allowedTypes.includes(actualType) || (allowedTypes.includes('integer') && isInt) || (allowedTypes.includes('number') && typeof data === 'number');
    if (!typeMatches) {
      throw new Error(`Validation error at ${path}: expected ${allowedTypes.join('|')}, got ${actualType}`);
    }
  }

  if (schema.enum && !schema.enum.includes(data)) {
    throw new Error(`Validation error at ${path}: value "${data}" is not in enum [${schema.enum.join(', ')}]`);
  }

  if (schema.pattern && typeof data === 'string') {
    const regex = new RegExp(schema.pattern);
    if (!regex.test(data)) {
      throw new Error(`Validation error at ${path}: "${data}" does not match pattern ${schema.pattern}`);
    }
  }

  if (schema.type === 'object' || (Array.isArray(schema.type) && schema.type.includes('object'))) {
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      if (schema.required) {
        for (const reqKey of schema.required) {
          if (!(reqKey in data)) {
            throw new Error(`Validation error at ${path}: missing required property "${reqKey}"`);
          }
        }
      }

      if (schema.additionalProperties === false && schema.properties) {
        for (const key of Object.keys(data)) {
          if (!(key in schema.properties)) {
            throw new Error(`Validation error at ${path}: undeclared property "${key}" violates additionalProperties: false`);
          }
        }
      }

      if (schema.properties) {
        for (const [key, propSchema] of Object.entries(schema.properties)) {
          if (key in data) {
            validateAgainstSchema(propSchema, data[key], `${path}.${key}`);
          }
        }
      }
    }
  }

  if (schema.type === 'array' || (Array.isArray(schema.type) && schema.type.includes('array'))) {
    if (Array.isArray(data) && schema.items) {
      for (let i = 0; i < data.length; i++) {
        validateAgainstSchema(schema.items, data[i], `${path}[${i}]`);
      }
    }
  }
}

describe('Schema Contracts and Instance Validation', () => {
  it('validates evidence.schema.json structure', async () => {
    const raw = await readFile(resolve('schemas/evidence.schema.json'), 'utf8');
    const schema = JSON.parse(raw);

    assert.equal(schema.title, 'EvidenceBundle');
    assert.ok(schema.required.includes('subjectDigest'));
    assert.ok(schema.required.includes('packages'));
    assert.ok(schema.properties.packages.items.required.includes('isDirect'));
    assert.ok('hasInstallScript' in schema.properties.packages.items.properties);
    assert.ok('provenance' in schema.properties.packages.items.properties);
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

  it('strictly validates real generated evidence bundles against evidence.schema.json', async () => {
    const schemaRaw = await readFile(resolve('schemas/evidence.schema.json'), 'utf8');
    const schema = JSON.parse(schemaRaw);

    const liveRaw = await readFile(resolve('reports/demo/live-benign/evidence.json'), 'utf8');
    const liveEvidence = JSON.parse(liveRaw);

    const suspRaw = await readFile(resolve('reports/demo/suspicious-fixture/evidence.json'), 'utf8');
    const suspEvidence = JSON.parse(suspRaw);

    // Strict validation must succeed with zero undeclared property errors
    assert.doesNotThrow(() => {
      validateAgainstSchema(schema, liveEvidence);
    });
    assert.doesNotThrow(() => {
      validateAgainstSchema(schema, suspEvidence);
    });
  });

  it('strictly rejects objects with undeclared properties when additionalProperties is false', async () => {
    const schemaRaw = await readFile(resolve('schemas/evidence.schema.json'), 'utf8');
    const schema = JSON.parse(schemaRaw);

    const invalidEvidence = {
      schemaVersion: '1.0',
      runId: 'run-1',
      mode: 'fixture',
      subjectDigest: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      scannerVersion: '0.1.0',
      policyDigest: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      collectionStatus: 'complete',
      packages: [
        {
          name: 'test-pkg',
          location: 'node_modules/test-pkg',
          changeType: 'added',
          isDirect: true,
          forbiddenUndeclaredField: true // should trigger failure
        }
      ],
      observations: [],
      unknowns: [],
      sources: []
    };

    assert.throws(
      () => validateAgainstSchema(schema, invalidEvidence),
      /forbiddenUndeclaredField.*violates additionalProperties/
    );
  });
});
