import { describe, expect, it, vi } from 'vitest';
import { executeWithJitterRetry } from '../src/index.js';

describe('executeWithJitterRetry', () => {
  it('retries a failed operation until it succeeds', async () => {
    let attempts = 0;
    const result = await executeWithJitterRetry(async () => {
      attempts++;
      if (attempts < 3) throw new Error('temporary failure');
      return 'ok';
    }, { maxRetries: 3, baseDelayMs: 0, maxDelayMs: 0 });
    expect(result).toBe('ok');
    expect(attempts).toBe(3);
  });
  it('preserves the final error and stops after configured retries', async () => {
    const failure = new Error('unavailable');
    let attempts = 0;
    await expect(executeWithJitterRetry(async () => {
      attempts++;
      throw failure;
    }, { maxRetries: 2, baseDelayMs: 0, maxDelayMs: 0 })).rejects.toBe(failure);
    expect(attempts).toBe(3);
  });
  it('stops when shouldRetry returns false', async () => {
    const operation = vi.fn().mockRejectedValue(new Error('invalid proof'));
    const shouldRetry = vi.fn().mockReturnValue(false);
    await expect(executeWithJitterRetry(operation, {
      baseDelayMs: 0, maxDelayMs: 0, shouldRetry,
    })).rejects.toThrow('invalid proof');
    expect(operation).toHaveBeenCalledTimes(1);
    expect(shouldRetry).toHaveBeenCalledWith(expect.any(Error), 1);
  });
  it.each([
    [{ maxRetries: Number.NaN }, 'maxRetries'],
    [{ maxRetries: Number.POSITIVE_INFINITY }, 'maxRetries'],
    [{ maxRetries: Number.MAX_SAFE_INTEGER + 1 }, 'maxRetries'],
    [{ maxRetries: -1 }, 'maxRetries'],
    [{ maxRetries: 1.5 }, 'maxRetries'],
    [{ baseDelayMs: Number.NaN }, 'baseDelayMs'],
    [{ baseDelayMs: Number.POSITIVE_INFINITY }, 'baseDelayMs'],
    [{ baseDelayMs: -1 }, 'baseDelayMs'],
    [{ maxDelayMs: Number.NaN }, 'maxDelayMs'],
    [{ maxDelayMs: Number.POSITIVE_INFINITY }, 'maxDelayMs'],
    [{ maxDelayMs: -1 }, 'maxDelayMs'],
  ])('rejects invalid options before invoking operation: %o', async (options, field) => {
    const operation = vi.fn().mockResolvedValue('ok');
    await expect(executeWithJitterRetry(operation, options)).rejects.toThrow(field);
    expect(operation).not.toHaveBeenCalled();
  });
  it.each(['yes', true, 1, {}])('rejects a non-function shouldRetry (%s) before running the operation', async (shouldRetry) => {
    const operation = vi.fn().mockRejectedValue(new Error('original failure'));
    await expect(executeWithJitterRetry(operation, {
      baseDelayMs: 0, maxDelayMs: 0, shouldRetry: shouldRetry as never,
    })).rejects.toThrow(TypeError);
    expect(operation).not.toHaveBeenCalled();
  });
});
