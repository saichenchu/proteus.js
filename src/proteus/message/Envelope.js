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

const MacKey = require('../derived/MacKey');
const Message = require('./Message');

/** @module message */

/** @class Envelope */
class Envelope {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param mac_key {derived.MacKey}
   * @param message {message.Message}
   * @returns {message.Envelope}
   */
  static new(mac_key, message) {
    TypeUtil.assert_is_instance(MacKey, mac_key);
    TypeUtil.assert_is_instance(Message, message);

    const message_enc = new Uint8Array(message.serialise());

    const env = ClassUtil.new_instance(Envelope);

    env.version = 1;
    env.mac = mac_key.sign(message_enc);
    env.message = message;
    env._message_enc = message_enc;

    Object.freeze(env);
    return env;
  }

  /**
   * @param mac_key {derived.MacKey}
   * @returns {boolean}
   */
  verify(mac_key) {
    TypeUtil.assert_is_instance(MacKey, mac_key);
    return mac_key.verify(this.mac, this._message_enc);
  }

  /** @returns {ArrayBuffer} The serialized message envelope */
  serialise() {
    const e = new CBOR.Encoder();
    this.encode(e);
    return e.get_buffer();
  }

  /**
   * @param buf {ArrayBuffer}
   * @returns {message.Envelope}
   */
  static deserialise(buf) {
    TypeUtil.assert_is_instance(ArrayBuffer, buf);

    const d = new CBOR.Decoder(buf);
    return Envelope.decode(d);
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
    e.object(1);
    e.u8(0);
    e.bytes(this.mac);

    e.u8(2);
    return e.bytes(this._message_enc);
  }

  /**
   * @param d {CBOR.Decoder}
   * @returns {message.Envelope}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const env = ClassUtil.new_instance(Envelope);

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          env.version = d.u8();
          break;
        case 1:
          const nprops_mac = d.object();
          for (let i = 0; i <= nprops_mac - 1; i++) {
            switch (d.u8()) {
              case 0:
                env.mac = new Uint8Array(d.bytes());
                break;
              default:
                d.skip();
            }
          }
          break;
        case 2:
          env._message_enc = new Uint8Array(d.bytes());
          break;
        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_integer(env.version);
    TypeUtil.assert_is_instance(Uint8Array, env.mac);

    env.message = Message.deserialise(env._message_enc.buffer);

    Object.freeze(env);
    return env;
  }
}

module.exports = Envelope;
