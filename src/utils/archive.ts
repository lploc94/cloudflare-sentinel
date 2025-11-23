/**
 * Archive utilities for long-term log storage
 * Exports D1 logs to R2 for cost-effective retention
 */

export interface ArchiveConfig {
  /** Batch size for reading from D1 */
  batchSize: number;
  /** Compress archives (gzip) */
  compress: boolean;
  /** Include metadata in archive */
  includeMetadata: boolean;
}

export interface ArchiveResult {
  success: boolean;
  archived: number;
  files: string[];
  totalSize: number;
  errors?: string[];
  duration: number;
}

/**
 * Archive old D1 logs to R2
 */
export async function archiveLogsToR2(
  db: D1Database,
  bucket: R2Bucket,
  cutoffTimestamp: number,
  config: ArchiveConfig
): Promise<ArchiveResult> {
  const startTime = Date.now();
  const errors: string[] = [];
  const files: string[] = [];
  let totalArchived = 0;
  let totalSize = 0;

  try {
    const archiveDate = new Date(cutoffTimestamp).toISOString().split('T')[0];
    let offset = 0;
    let fileIndex = 0;

    while (true) {
      // Fetch batch of old logs
      const logs = await db.prepare(`
        SELECT *
        FROM security_events
        WHERE timestamp < ?
        ORDER BY timestamp ASC
        LIMIT ? OFFSET ?
      `).bind(cutoffTimestamp, config.batchSize, offset).all();

      if (!logs.results || logs.results.length === 0) {
        break;
      }

      // Convert to JSONL format (JSON Lines)
      const jsonl = logs.results.map(log => JSON.stringify(log)).join('\n');
      
      // Prepare R2 key
      const key = `sentinel-archives/${archiveDate}/logs-${String(fileIndex).padStart(4, '0')}.jsonl`;
      
      let content: string | ArrayBuffer = jsonl;
      let contentType = 'application/x-ndjson';
      
      // Optional: Compress with gzip
      if (config.compress) {
        // Note: In Workers, use CompressionStream
        const encoder = new TextEncoder();
        const stream = new ReadableStream({
          start(controller) {
            controller.enqueue(encoder.encode(jsonl));
            controller.close();
          },
        });

        const compressed = stream.pipeThrough(new CompressionStream('gzip'));
        const reader = compressed.getReader();
        const chunks: Uint8Array[] = [];
        
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }

        // Combine chunks
        const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
        const combined = new Uint8Array(totalLength);
        let position = 0;
        for (const chunk of chunks) {
          combined.set(chunk, position);
          position += chunk.length;
        }

        content = combined.buffer;
        contentType = 'application/gzip';
      }

      // Upload to R2
      await bucket.put(key, content, {
        httpMetadata: {
          contentType,
        },
        customMetadata: config.includeMetadata ? {
          count: logs.results.length.toString(),
          archived_at: new Date().toISOString(),
          cutoff_timestamp: cutoffTimestamp.toString(),
          compressed: config.compress.toString(),
        } : undefined,
      });

      files.push(key);
      totalArchived += logs.results.length;
      totalSize += typeof content === 'string' ? content.length : content.byteLength;

      offset += config.batchSize;
      fileIndex++;

      // Prevent timeout
      if (offset % (config.batchSize * 10) === 0) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }

    return {
      success: true,
      archived: totalArchived,
      files,
      totalSize,
      duration: Date.now() - startTime,
    };
  } catch (error: any) {
    errors.push(error.message);
    return {
      success: false,
      archived: totalArchived,
      files,
      totalSize,
      errors,
      duration: Date.now() - startTime,
    };
  }
}

/**
 * List available archives in R2
 */
export async function listArchives(
  bucket: R2Bucket,
  prefix: string = 'sentinel-archives/'
): Promise<{
  archives: Array<{
    key: string;
    size: number;
    uploaded: Date;
    metadata?: Record<string, string>;
  }>;
}> {
  const listed = await bucket.list({ prefix });
  
  const archives = listed.objects.map(obj => ({
    key: obj.key,
    size: obj.size,
    uploaded: obj.uploaded,
    metadata: obj.customMetadata,
  }));

  return { archives };
}

/**
 * Restore logs from R2 archive
 */
export async function restoreLogsFromR2(
  bucket: R2Bucket,
  archiveKey: string
): Promise<{
  logs: any[];
  metadata?: Record<string, string>;
}> {
  const object = await bucket.get(archiveKey);
  
  if (!object) {
    throw new Error(`Archive not found: ${archiveKey}`);
  }

  let content = await object.text();
  
  // Check if compressed
  if (object.httpMetadata?.contentType === 'application/gzip') {
    // Decompress
    const arrayBuffer = await object.arrayBuffer();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(arrayBuffer));
        controller.close();
      },
    });

    const decompressed = stream.pipeThrough(new DecompressionStream('gzip'));
    const reader = decompressed.getReader();
    const chunks: Uint8Array[] = [];
    
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    const decoder = new TextDecoder();
    content = decoder.decode(
      new Uint8Array(
        chunks.reduce((acc, chunk) => {
          const combined = new Uint8Array(acc.length + chunk.length);
          combined.set(acc);
          combined.set(chunk, acc.length);
          return combined;
        }, new Uint8Array(0))
      )
    );
  }

  // Parse JSONL
  const logs = content
    .split('\n')
    .filter(line => line.trim())
    .map(line => JSON.parse(line));

  return {
    logs,
    metadata: object.customMetadata,
  };
}

/**
 * Delete old archives from R2
 */
export async function deleteOldArchives(
  bucket: R2Bucket,
  retentionDays: number,
  prefix: string = 'sentinel-archives/'
): Promise<{
  deleted: number;
  freedSpace: number;
}> {
  const cutoff = Date.now() - (retentionDays * 24 * 60 * 60 * 1000);
  const listed = await bucket.list({ prefix });
  
  let deleted = 0;
  let freedSpace = 0;

  for (const obj of listed.objects) {
    if (obj.uploaded.getTime() < cutoff) {
      await bucket.delete(obj.key);
      deleted++;
      freedSpace += obj.size;
    }
  }

  return { deleted, freedSpace };
}

/**
 * Recommended archive configurations
 */
export const ARCHIVE_CONFIGS = {
  /** Fast archiving, larger files */
  FAST: {
    batchSize: 5000,
    compress: false,
    includeMetadata: true,
  },

  /** Balanced - good compression */
  BALANCED: {
    batchSize: 2000,
    compress: true,
    includeMetadata: true,
  },

  /** Max compression, smaller files */
  COMPRESSED: {
    batchSize: 1000,
    compress: true,
    includeMetadata: false,
  },
};
