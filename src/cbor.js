// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview A minimal CBOR (RFC 8949) decoder: enough to read
 * authenticator data's credential public key & extension outputs.  Only
 * definite lengths, and no floats or tags.
 */

/**
 * Decode one CBOR item.
 *
 * @param {!Uint8Array} bytes
 * @param {number} offset Where the item starts.
 * @return {{value: *, end: number}} The item (a Map for maps, a Uint8Array
 *     for byte strings), & where it ends.
 */
export function decodeCbor(bytes, offset) {
  const need = (n) => {
    if (offset + n > bytes.length) {
      throw new Error('truncated CBOR');
    }
  };
  need(1);
  const major = bytes[offset] >> 5;
  const info = bytes[offset] & 0x1f;
  offset++;
  let arg;
  if (info < 24) {
    arg = info;
  } else if (info <= 27) {
    const size = 1 << (info - 24);  // 1, 2, 4 or 8 bytes.
    need(size);
    arg = 0;
    for (let i = 0; i < size; i++) {
      arg = arg * 256 + bytes[offset++];
    }
  } else {
    throw new Error('unsupported CBOR');
  }

  switch (major) {
    case 0:  // Unsigned integer.
      return {value: arg, end: offset};
    case 1:  // Negative integer.
      return {value: -1 - arg, end: offset};
    case 2:  // Byte string.
    case 3: {  // Text string.
      need(arg);
      const data = bytes.subarray(offset, offset + arg);
      return {
        value: major === 2 ? data : new TextDecoder().decode(data),
        end: offset + arg,
      };
    }
    case 4: {  // Array.
      const value = [];
      for (let i = 0; i < arg; i++) {
        let item;
        ({value: item, end: offset} = decodeCbor(bytes, offset));
        value.push(item);
      }
      return {value, end: offset};
    }
    case 5: {  // Map.
      const value = new Map();
      for (let i = 0; i < arg; i++) {
        let key;
        let item;
        ({value: key, end: offset} = decodeCbor(bytes, offset));
        ({value: item, end: offset} = decodeCbor(bytes, offset));
        value.set(key, item);
      }
      return {value, end: offset};
    }
    case 7:  // Simple values.
      if (arg === 20 || arg === 21) {
        return {value: arg === 21, end: offset};
      }
      if (arg === 22) {
        return {value: null, end: offset};
      }
  }
  throw new Error('unsupported CBOR');
}
