import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { isSafeArchivePath, parseTarBuffer, inspectTgzArchive } from '../src/archive.mjs';

/**
 * Helper to construct an in-memory 512-byte tar header block.
 */
function createTarHeader(name, size, typeflag = '0') {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  header.write(size.toString(8).padStart(11, '0'), 124, 12, 'utf8');
  header.write(typeflag, 156, 1, 'utf8');
  header.write('ustar\0', 257, 6, 'utf8');
  return header;
}

describe('Archive Inspector & Decompression Defense Tests', () => {
  it('validates safe and hostile paths accurately', () => {
    assert.equal(isSafeArchivePath('package/index.js'), true);
    assert.equal(isSafeArchivePath('lib/utils/helper.mjs'), true);

    // Hostile traversal paths
    assert.equal(isSafeArchivePath('../outside.js'), false);
    assert.equal(isSafeArchivePath('foo/../../bar.js'), false);
    assert.equal(isSafeArchivePath('/etc/passwd'), false);
    assert.equal(isSafeArchivePath('C:\\Windows\\system32'), false);
  });

  it('rejects archive entries containing directory traversal', () => {
    const maliciousHeader = createTarHeader('../../evil.sh', 10);
    const content = Buffer.alloc(512);
    const tarBuf = Buffer.concat([maliciousHeader, content]);

    assert.throws(() => parseTarBuffer(tarBuf), /Hostile archive entry path detected/);
  });

  it('rejects symlinks in archive', () => {
    const symlinkHeader = createTarHeader('symlink-file', 0, '2'); // '2' is symlink
    assert.throws(() => parseTarBuffer(symlinkHeader), /Unsupported symlink/);
  });

  it('parses valid in-memory tar archive without writing to disk', () => {
    const fileContent = 'console.log("hello world");';
    const header = createTarHeader('package/index.js', fileContent.length);
    const body = Buffer.alloc(512);
    body.write(fileContent, 0, 'utf8');
    const endBlock = Buffer.alloc(1024); // two 512-byte zero blocks

    const tarBuf = Buffer.concat([header, body, endBlock]);
    const tgzBuf = gzipSync(tarBuf);

    const result = inspectTgzArchive(tgzBuf);
    assert.equal(result.entryCount, 1);
    assert.equal(result.files.length, 1);
    assert.equal(result.files[0].path, 'index.js');
    assert.equal(result.files[0].content, fileContent);
    assert.match(result.integrity, /^sha512-/);
  });

  it('tracks large files in omittedFiles rather than silently dropping them', () => {
    // 1.5 MiB file (exceeds 1 MiB limit)
    const largeSize = 1.5 * 1024 * 1024;
    const header = createTarHeader('package/large-bundle.js', largeSize);
    const padding = Buffer.alloc(Math.ceil(largeSize / 512) * 512);
    const endBlock = Buffer.alloc(1024);

    const tarBuf = Buffer.concat([header, padding, endBlock]);
    const result = parseTarBuffer(tarBuf, {
      MAX_COMPRESSED_SIZE: 10 * 1024 * 1024,
      MAX_EXPANDED_SIZE: 50 * 1024 * 1024,
      MAX_ENTRIES: 5000,
      MAX_TEXT_FILE_SIZE: 1 * 1024 * 1024
    });

    assert.equal(result.files.length, 0);
    assert.equal(result.omittedFiles.length, 1);
    assert.equal(result.omittedFiles[0].path, 'large-bundle.js');
    assert.match(result.omittedFiles[0].reason, /exceeds text inspection limit/);
  });

  it('enforces maximum expanded size during decompression (zip bomb defense)', () => {
    // Generate buffer that decompresses to more than limits.MAX_EXPANDED_SIZE
    const tinyLimits = {
      MAX_COMPRESSED_SIZE: 10 * 1024 * 1024,
      MAX_EXPANDED_SIZE: 1024, // 1 KB limit
      MAX_ENTRIES: 100,
      MAX_TEXT_FILE_SIZE: 512
    };

    const bigPayload = Buffer.alloc(10 * 1024, 'a'); // 10 KB of 'a'
    const compressed = gzipSync(bigPayload);

    assert.throws(
      () => inspectTgzArchive(compressed, tinyLimits),
      /Expanded archive exceeds limit.*zip bomb/
    );
  });
});
