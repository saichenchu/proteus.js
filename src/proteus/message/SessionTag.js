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
  } catch (err) {}
}

const DontCallConstructor = require('../errors/DontCallConstructor');

const ClassUtil = require('../util/ClassUtil');
const TypeUtil = require('../util/TypeUtil');

const DecodeError = require('../errors/DecodeError');
const RandomUtil = require('../util/RandomUtil');

module.exports = class SessionTag {
  constructor() {
    throw new DontCallConstructor(this);
  }

  static new() {
    const st = ClassUtil.new_instance(SessionTag);
    st.tag = RandomUtil.random_bytes(16);
    return st;
  }

  toString() {
    return sodium.to_hex(this.tag);
  }

  encode(e) {
    return e.bytes(this.tag);
  }

  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const bytes = new Uint8Array(d.bytes());
    if (bytes.byteLength !== 16) {
      throw DecodeError.InvalidArrayLen(
        `SessionTag should be 16 bytes, not ${bytes.byteLength} bytes.`
      );
    }

    const st = ClassUtil.new_instance(SessionTag);
    st.tag = new Uint8Array(bytes);
    return st;
  }
};
