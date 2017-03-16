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

const ClassUtil = require('../util/ClassUtil');
const DontCallConstructor = require('../errors/DontCallConstructor');
const TypeUtil = require('../util/TypeUtil');

const IdentityKey = require('./IdentityKey');
const KeyPair = require('./KeyPair');
const SecretKey = require('./SecretKey');

/** @module keys */

/** @class IdentityKeyPair */
class IdentityKeyPair {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /** @returns {keys.IdentityKeyPair} */
  static new() {
    const key_pair = KeyPair.new();

    /** @type {keys.IdentityKeyPair} */
    const ikp = ClassUtil.new_instance(IdentityKeyPair);
    ikp.version = 1;
    ikp.secret_key = key_pair.secret_key;
    ikp.public_key = IdentityKey.new(key_pair.public_key);

    return ikp;
  }

  /** @returns {ArrayBuffer} */
  serialise() {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  /**
   * @param buf {ArrayBuffer}
   * @returns {keys.IdentityKeyPair}
   */
  static deserialise(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);

    const d = new CBOR.Decoder(buf);
    return IdentityKeyPair.decode(d);
  }

  /**
   * @param e {CBOR.Encoder}
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    e.object(3);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    this.secret_key.encode(e);
    e.u8(2);
    return this.public_key.encode(e);
  }

  /**
   * @param d {CBOR.Decoder}
   * @returns {keys.IdentityKeyPair}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(IdentityKeyPair);

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.version = d.u8();
          break;
        case 1:
          self.secret_key = SecretKey.decode(d);
          break;
        case 2:
          self.public_key = IdentityKey.decode(d);
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_instance(SecretKey, self.secret_key);
    TypeUtil.assert_is_instance(IdentityKey, self.public_key);

    return self;
  }
}

module.exports = IdentityKeyPair;
