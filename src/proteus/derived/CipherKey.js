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

const CBOR = require('wire-webapp-cbor');
const sodium = require('libsodium-wrappers-sumo');
if (typeof window === 'undefined') {
  try {
    const sodium_neon = require('libsodium-neon');
    Object.assign(sodium, sodium_neon);
  } catch (err) {
    // fall back to libsodium.js
  }
}

const ClassUtil = require('../util/ClassUtil');
const DontCallConstructor = require('../errors/DontCallConstructor');
const TypeUtil = require('../util/TypeUtil');

/** @module derived */

/** @class CipherKey */
class CipherKey {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param {Uint8Array} key
   * @returns {derived.CipherKey}
   */
  static new(key) {
    TypeUtil.assert_is_instance(Uint8Array, key);

    const ck = ClassUtil.new_instance(CipherKey);
    /** @type {Uint8Array} */
    ck.key = key;
    return ck;
  }

  /**
   * @param {ArrayBuffer|String|Uint8Array} plaintext - The text to encrypt
   * @param {Uint8Array} nonce - Counter as nonce
   * @returns {Uint8Array} Encrypted payload
   */
  encrypt(plaintext, nonce) {
    // @todo Re-validate if the ArrayBuffer check is needed (Prerequisite: Integration tests)
    if (plaintext instanceof ArrayBuffer && plaintext.byteLength !== undefined) {
      plaintext = new Uint8Array(plaintext);
    }

    return sodium.crypto_stream_chacha20_xor(plaintext, nonce, this.key, 'uint8array');
  }

  /**
   * @param {Uint8Array} ciphertext
   * @param {Uint8Array} nonce
   * @returns {Uint8Array}
   */
  decrypt(ciphertext, nonce) {
    return this.encrypt(ciphertext, nonce);
  }

  /**
   * @param {CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(1);
    e.u8(0);
    return e.bytes(this.key);
  }

  /**
   * @param {CBOR.Encoder} d
   * @returns {derived.CipherKey}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    let key_bytes = null;

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          key_bytes = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }
    return CipherKey.new(key_bytes);
  }
}

module.exports = CipherKey;
