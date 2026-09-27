import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';

/**
 * Resource limits for archive inspection (Section 8 of Guide)
 */
export const ARCHIVE_LIMITS = {
  MAX_COMPRESSED_SIZE: 10 * 1024 * 1024,      // 10 MiB
  MAX_EXPANDED_SIZE: 50 * 1024 * 1024,        // 50 MiB
  MAX_ENTRIES: 5000,                          // 5,000 entries
  MAX_TEXT_FILE_SIZE: 1 * 1024 * 1024         // 1 MiB per inspected text file
};

/**
 * Validates tar entry path to prevent directory traversal or absolute write vectors.
 * @param {string} path 
 * @returns {boolean} True if safe, false if traversal/hostile
 */
export function isSafeArchivePath(path) {
  if (!path || typeof path !== 'string') return false;
  // Reject absolute paths
  if (path.startsWith('/') || path.startsWith('\\') || /^[a-zA-Z]:/.test(path)) {
    return false;
  }
  // Reject traversal sequences
  const segments = path.replace(/\\/g, '/').split('/');
  for (const seg of segments) {
    if (seg === '..' || seg === '') {
      // Empty segment is ok only if trailing slash, but '..' is never safe
      if (seg === '..') return false;
    }
  }
  return true;
}

/**
 * Parses an in-memory uncompressed tar buffer.
 * Pure Node.js zero-dependency implementation of ustar/POSIX tar format.
 * @param {Buffer} tarBuffer 
 * @param {object} limits 
 * @returns {{ files: Array<{ path: string, content: string, size: number }>, omittedFiles: Array<{ path: string, size: number, reason: string }>, totalSize: number, entryCount: number, truncated: boolean, truncationReason: string|null }}
 */
export function parseTarBuffer(tarBuffer, limits = ARCHIVE_LIMITS) {
  const files = [];
  const omittedFiles = [];
  let offset = 0;
  let totalExpanded = 0;
  let entryCount = 0;
  let truncated = false;
  let truncationReason = null;

  while (offset + 512 <= tarBuffer.length) {
    const header = tarBuffer.subarray(offset, offset + 512);

    // Check for empty block (end of archive)
    const isZeroBlock = header.every((b) => b === 0);
    if (isZeroBlock) {
      break;
    }

    entryCount++;
    if (entryCount > limits.MAX_ENTRIES) {
      truncated = true;
      truncationReason = `Archive entry count (${entryCount}) exceeded limit of ${limits.MAX_ENTRIES}`;
      break;
    }

    // Read header fields
    const rawName = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '').trim();
    const rawSize = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = parseInt(rawSize, 8) || 0;
    const typeflag = String.fromCharCode(header[156] || 0);

    const rawPrefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '').trim();
    const fullPath = rawPrefix ? `${rawPrefix}/${rawName}` : rawName;

    offset += 512;

    // Defensive check: traversal / hostile path
    if (!isSafeArchivePath(fullPath)) {
      throw new Error(`Hostile archive entry path detected: "${fullPath}"`);
    }

    // Typeflag '0' or '\0' is regular file
    const isRegularFile = typeflag === '0' || typeflag === '\0' || typeflag === '';
    const isSymlink = typeflag === '1' || typeflag === '2';

    if (isSymlink) {
      throw new Error(`Unsupported symlink/hardlink in archive: "${fullPath}"`);
    }

    totalExpanded += size;
    if (totalExpanded > limits.MAX_EXPANDED_SIZE) {
      truncated = true;
      truncationReason = `Total expanded size (${totalExpanded} bytes) exceeded limit of ${limits.MAX_EXPANDED_SIZE} bytes`;
      break;
    }

    const normalizedPath = fullPath.replace(/^package\//, '');

    if (isRegularFile && size > 0) {
      const fileBytes = tarBuffer.subarray(offset, offset + size);
      if (size <= limits.MAX_TEXT_FILE_SIZE) {
        files.push({
          path: normalizedPath,
          content: fileBytes.toString('utf8'),
          size
        });
      } else {
        // Track omitted large files rather than silently ignoring
        omittedFiles.push({
          path: normalizedPath,
          size,
          reason: `File size (${size} bytes) exceeds text inspection limit of ${limits.MAX_TEXT_FILE_SIZE} bytes`
        });
      }
    }

    // Advance offset to next 512-byte boundary
    const paddedSize = Math.ceil(size / 512) * 512;
    offset += paddedSize;
  }

  return {
    files,
    omittedFiles,
    totalSize: totalExpanded,
    entryCount,
    truncated,
    truncationReason
  };
}

/**
 * Decompresses and inspects an npm .tgz buffer in memory without writing to disk.
 * Limits are enforced during decompression to protect against zip bombs.
 * @param {Buffer} tgzBuffer 
 * @param {object} limits 
 * @returns {{ files: Array<{ path: string, content: string, size: number }>, omittedFiles: Array<{ path: string, size: number, reason: string }>, totalSize: number, entryCount: number, integrity: string, truncated: boolean, truncationReason: string|null }}
 */
export function inspectTgzArchive(tgzBuffer, limits = ARCHIVE_LIMITS) {
  if (tgzBuffer.length > limits.MAX_COMPRESSED_SIZE) {
    throw new Error(
      `Archive compressed size (${tgzBuffer.length} bytes) exceeds limit (${limits.MAX_COMPRESSED_SIZE} bytes)`
    );
  }

  // Calculate actual SRI sha512 integrity string
  const sha512Base64 = createHash('sha512').update(tgzBuffer).digest('base64');
  const actualIntegrity = `sha512-${sha512Base64}`;

  let tarBuffer;
  try {
    // Enforce maxOutputLength during decompression to prevent zip bomb attacks
    tarBuffer = gunzipSync(tgzBuffer, {
      maxOutputLength: limits.MAX_EXPANDED_SIZE + 1024
    });
  } catch (err) {
    if (err.code === 'ERR_BUFFER_TOO_LARGE' || (err.message && err.message.includes('output length'))) {
      throw new Error(
        `Expanded archive exceeds limit of ${limits.MAX_EXPANDED_SIZE} bytes during decompression (zip bomb defense)`
      );
    }
    throw new Error(`Failed to decompress gzip archive: ${err.message}`);
  }

  const result = parseTarBuffer(tarBuffer, limits);
  return {
    ...result,
    integrity: actualIntegrity
  };
}
