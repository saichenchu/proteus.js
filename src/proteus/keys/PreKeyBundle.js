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

const ClassUtil = require('../util/ClassUtil');
const DontCallConstructor = require('../errors/DontCallConstructor');
const TypeUtil = require('../util/TypeUtil');

const IdentityKey = require('./IdentityKey');
const IdentityKeyPair = require('./IdentityKeyPair');
const PreKey = require('./PreKey');
const PreKeyAuth = require('./PreKeyAuth');
const PublicKey = require('./PublicKey');

/** @module keys */

/** @class PreKeyBundle */
class PreKeyBundle {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param public_identity_key {keys.IdentityKey}
   * @param prekey {keys.PreKey}
   * @returns {keys.PreKeyBundle}
   */
  static new(public_identity_key, prekey) {
    TypeUtil.assert_is_instance(IdentityKey, public_identity_key);
    TypeUtil.assert_is_instance(PreKey, prekey);

    const bundle = ClassUtil.new_instance(PreKeyBundle);

    bundle.version = 1;
    bundle.prekey_id = prekey.key_id;
    bundle.public_key = prekey.key_pair.public_key;
    bundle.identity_key = public_identity_key;
    bundle.signature = null;

    return bundle;
  }

  /**
   * @param identity_pair {keys.IdentityKeyPair}
   * @param prekey {keys.PreKey}
   * @returns {keys.PreKeyBundle}
   */
  static signed(identity_pair, prekey) {
    TypeUtil.assert_is_instance(IdentityKeyPair, identity_pair);
    TypeUtil.assert_is_instance(PreKey, prekey);

    /** @type {keys.PublicKey} */
    const ratchet_key = prekey.key_pair.public_key;
    /** @type {Uint8Array} */
    const signature = identity_pair.secret_key.sign(ratchet_key.pub_edward);

    /** @type {keys.PreyKeyBundle} */
    const bundle = ClassUtil.new_instance(PreKeyBundle);

    bundle.version = 1;
    bundle.prekey_id = prekey.key_id;
    bundle.public_key = ratchet_key;
    bundle.identity_key = identity_pair.public_key;
    bundle.signature = signature;

    return bundle;
  }

  /** @returns {keys.PreKeyAuth} */
  verify() {
    if (!this.signature) {
      return PreKeyAuth.UNKNOWN;
    }

    if (this.identity_key.public_key.verify(this.signature, this.public_key.pub_edward)) {
      return PreKeyAuth.VALID;
    }
    return PreKeyAuth.INVALID;
  }

  /** @returns {ArrayBuffer} */
  serialise() {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  /** @returns {{id: (number), key: *}} */
  serialised_json() {
    return {
      'id': this.prekey_id,
      'key': sodium.to_base64(new Uint8Array(this.serialise()), true)
    };
  }

  /**
   * @param buf {ArrayBuffer}
   * @returns {keys.PreKeyBundle}
   */
  static deserialise(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);
    return PreKeyBundle.decode(new CBOR.Decoder(buf));
  }

  /**
   * @param e {CBOR.Encoder}
   * @returns {CBOR.Encoder}
   */
  encode(e) {
    TypeUtil.assert_is_instance(CBOR.Encoder, e);

    e.object(5);
    e.u8(0);
    e.u8(this.version);
    e.u8(1);
    e.u16(this.prekey_id);
    e.u8(2);
    this.public_key.encode(e);
    e.u8(3);
    this.identity_key.encode(e);

    e.u8(4);
    if (!this.signature) {
      return e.null();
    } else {
      return e.bytes(this.signature);
    }
  }

  /**
   * @param d {CBOR.Decoder}
   * @returns {keys.PreKeyBundle}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(PreKeyBundle);

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.version = d.u8();
          break;
        case 1:
          self.prekey_id = d.u16();
          break;
        case 2:
          self.public_key = PublicKey.decode(d);
          break;
        case 3:
          self.identity_key = IdentityKey.decode(d);
          break;
        case 4:
          self.signature = d.optional(() => new Uint8Array(d.bytes()));
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_integer(self.version);
    TypeUtil.assert_is_integer(self.prekey_id);
    TypeUtil.assert_is_instance(PublicKey, self.public_key);
    TypeUtil.assert_is_instance(IdentityKey, self.identity_key);

    return self;
  }
}

module.exports = PreKeyBundle;
