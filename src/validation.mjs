import { readFileSync } from 'node:fs';

// Covers the JSON Schema keywords used by this project's local contracts.
export function validateAgainstSchema(schema, data, path = '$') {
  const types = schema.type ? [schema.type].flat() : [];
  const actual = data === null ? 'null' : Array.isArray(data) ? 'array' : typeof data;
  if (types.length && !types.includes(actual) && !(types.includes('integer') && Number.isInteger(data))) {
    throw new Error(`${path}: expected ${types.join('|')}, got ${actual}`);
  }
  if (schema.enum && !schema.enum.includes(data)) throw new Error(`${path}: invalid enum value`);
  if (typeof data === 'string') {
    if (schema.pattern && !new RegExp(schema.pattern).test(data)) throw new Error(`${path}: invalid pattern`);
    if (schema.minLength && data.length < schema.minLength) throw new Error(`${path}: string too short`);
  }
  if (data && actual === 'object') {
    for (const key of schema.required || []) {
      if (!Object.hasOwn(data, key)) throw new Error(`${path}: missing required property ${key}`);
    }
    for (const key of Object.keys(data)) {
      if (Object.hasOwn(schema.properties || {}, key)) {
        validateAgainstSchema(schema.properties[key], data[key], `${path}.${key}`);
      } else if (schema.additionalProperties === false) {
        throw new Error(`${path}.${key}: violates additionalProperties`);
      }
    }
  }
  if (Array.isArray(data) && schema.items) data.forEach((item, i) => validateAgainstSchema(schema.items, item, `${path}[${i}]`));
}

export function loadSchema(name) {
  return JSON.parse(readFileSync(new URL(`../schemas/${name}.schema.json`, import.meta.url), 'utf8'));
}
