/*
 * Wire
 * Copyright (C) 2016 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

'use strict';

const sodium = require('libsodium-wrappers-sumo');
if (typeof window === 'undefined') {
  try {
    const sodium_neon = require('libsodium-neon');
    Object.assign(sodium, sodium_neon);
  } catch (err) {
    // fall back to libsodium.js
  }
}

const ArrayUtil = require('../util/ArrayUtil');
const MemoryUtil = require('../util/MemoryUtil');
const TypeUtil = require('../util/TypeUtil');

/** @module util */

const KeyDerivationUtil = {
  /**
   * HMAC-based Key Derivation Function
   *
   * @param {Uint8Array|string} salt
   * @param {Uint8Array|string} input - Initial Keying Material (IKM)
   * @param {Uint8Array|string} info - Key Derivation Data (Info)
   * @param {number} length - Length of the derived key in bytes (L)
   * @returns {Uint8Array} Output Keying Material (OKM)
   */
  hkdf(salt, input, info, length) {
    const convert_type = (value) => {
      if (typeof value === 'string') {
        return sodium.from_string(value);
      }
      TypeUtil.assert_is_instance(Uint8Array, value);
      return value;
    };

    salt = convert_type(salt);
    input = convert_type(input);
    info = convert_type(info);

    TypeUtil.assert_is_integer(length);

    const HASH_LEN = 32;

    /**
     * @param {*} salt
     * @returns {Uint8Array}
     */
    const salt_to_key = (salt) => {
      const keybytes = sodium.crypto_auth_hmacsha256_KEYBYTES;
      if (salt.length > keybytes) {
        return sodium.crypto_hash_sha256(salt);
      }

      const key = new Uint8Array(keybytes);
      key.set(salt);
      return key;
    };

    /**
     * @param {*} salt
     * @param {*} input
     * @returns {*}
     */
    const extract = (salt, input) => {
      return sodium.crypto_auth_hmacsha256(input, salt_to_key(salt));
    };

    /**
     * @param {*} tag
     * @param {*} info
     * @param {number} length
     * @returns {Uint8Array}
     */
    const expand = (tag, info, length) => {
      let num_blocks = Math.ceil(length / HASH_LEN);
      let hmac = new Uint8Array(0);
      let result = new Uint8Array(0);

      for (let i = 0; i <= num_blocks - 1; i++) {
        const buf = ArrayUtil.concatenate_array_buffers([hmac, info, new Uint8Array([i + 1])]);
        hmac = sodium.crypto_auth_hmacsha256(buf, tag);
        result = ArrayUtil.concatenate_array_buffers([result, hmac]);
      }

      return new Uint8Array(result.buffer.slice(0, length));
    };

    const key = extract(salt, input);

    MemoryUtil.zeroize(input);
    MemoryUtil.zeroize(salt);

    return expand(key, info, length);
  },
};

module.exports = KeyDerivationUtil;
