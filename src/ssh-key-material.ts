const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;

/** Copy pasted PEM/OpenSSH text for ssh-add without changing the stored secret. */
export function normalizeSshPrivateKey(value: string | Buffer): Buffer {
  const size = Buffer.isBuffer(value) ? value.length : Buffer.byteLength(value, 'utf8');
  if (size > MAX_PRIVATE_KEY_BYTES) throw new Error('SSH private key is too large');
  const source = Buffer.from(value);
  try {
    const whitespace = (byte: number) => byte === 32 || (byte >= 9 && byte <= 13);
    let start = 0;
    let end = source.length;
    while (start < end && whitespace(source[start])) start++;
    while (end > start && whitespace(source[end - 1])) end--;
    if (start === end) throw new Error('SSH private key is empty');
    // Use bytes so Buffer credentials do not create an unerasable string copy.
    const result = Buffer.alloc(end - start + 1);
    let written = 0;
    for (let index = start; index < end; index++) {
      if (source[index] === 13 && source[index + 1] === 10) continue;
      result[written++] = source[index];
    }
    result[written++] = 10;
    return result.subarray(0, written);
  } finally {
    source.fill(0);
  }
}
