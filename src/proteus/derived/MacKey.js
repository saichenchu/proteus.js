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

const ClassUtil = require('../util/ClassUtil');
const DontCallConstructor = require('../errors/DontCallConstructor');
const TypeUtil = require('../util/TypeUtil');

/** @module derived */

/** @class MacKey */
class MacKey {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param key {Uint8Array} Mac Key in byte array format generated by derived secrets
   * @returns {derived.MacKey}
   */
  static new(key) {
    TypeUtil.assert_is_instance(Uint8Array, key);

    const mk = ClassUtil.new_instance(MacKey);
    /** @type {Uint8Array} */
    mk.key = key;
    return mk;
  }

  /**
   * Hash-based message authentication code
   * @param msg {string|Uint8Array}
   * @returns {Uint8Array}
   */
  sign(msg) {
    return sodium.crypto_auth_hmacsha256(msg, this.key);
  }

  /**
   * @param signature {Uint8Array}
   * @param msg {Uint8Array}
   * @returns {boolean}
   */
  verify(signature, msg) {
    return sodium.crypto_auth_hmacsha256_verify(signature, msg, this.key);
  }

  /**
   * @param e {CBOR.Encoder}
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(1);
    e.u8(0);
    return e.bytes(this.key);
  }

  /**
   * @param d {CBOR.Decoder}
   * @returns {derived.MacKey}
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

    return MacKey.new(key_bytes);
  }
};

module.exports = MacKey;
