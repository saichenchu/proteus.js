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

const PublicKey = require('./PublicKey');

/** @module keys */

/**
 * Construct a long-term identity key pair.
 * @classdesc Every client has a long-term identity key pair.
 * Long-term identity keys are used to initialise "sessions" with other clients (triple DH).
 */
class IdentityKey {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param {keys.IdentityKey} public_key
   * @returns {keys.IdentityKey}
   */
  static new(public_key) {
    TypeUtil.assert_is_instance(PublicKey, public_key);

    const key = ClassUtil.new_instance(IdentityKey);
    key.public_key = public_key;
    return key;
  }

  /** @returns {string} */
  fingerprint() {
    return this.public_key.fingerprint();
  }

  /** @returns {string} */
  toString() {
    return sodium.to_hex(this.public_key);
  }

  /**
   * @param {CBOR.Encoder} e
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(1);
    e.u8(0);
    return this.public_key.encode(e);
  }

  /**
   * @param {CBOR.Decoder} d
   * @returns {keys.IdentityKey}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    let public_key = null;

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          public_key = PublicKey.decode(d);
          break;
        default:
          d.skip();
      }
    }

    return IdentityKey.new(public_key);
  }
}

module.exports = IdentityKey;
