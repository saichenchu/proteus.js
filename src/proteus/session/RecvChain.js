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

const PublicKey = require('../keys/PublicKey');

const DecryptError = require('../errors/DecryptError');
const ProteusError = require('../errors/ProteusError');

const CipherMessage = require('../message/CipherMessage');
const Envelope = require('../message/Envelope');

const ChainKey = require('./ChainKey');
const MessageKeys = require('./MessageKeys');

/** @module session */

/** @class RecvChain */
class RecvChain {
  constructor() {
    throw new DontCallConstructor(this);
  }

  /**
   * @param chain_key {session.ChainKey}
   * @param public_key {keys.PublicKey}
   * @returns {message.PreKeyMessage}
   */
  static new(chain_key, public_key) {
    TypeUtil.assert_is_instance(ChainKey, chain_key);
    TypeUtil.assert_is_instance(PublicKey, public_key);

    const rc = ClassUtil.new_instance(RecvChain);
    rc.chain_key = chain_key;
    rc.ratchet_key = public_key;
    rc.message_keys = [];
    return rc;
  }

  /**
   * @param envelope {message.Envelope}
   * @param msg {message.CipherMessage}
   * @returns {Uint8Array}
   */
  try_message_keys(envelope, msg) {
    TypeUtil.assert_is_instance(Envelope, envelope);
    TypeUtil.assert_is_instance(CipherMessage, msg);

    if (this.message_keys[0] && this.message_keys[0].counter > msg.counter) {
      throw new DecryptError.OutdatedMessage();
    }

    const idx = this.message_keys.findIndex((mk) => {
      return mk.counter === msg.counter;
    });

    if (idx === -1) {
      throw new DecryptError.DuplicateMessage();
    }

    const mk = this.message_keys.splice(idx, 1)[0];
    if (!envelope.verify(mk.mac_key)) {
      throw new DecryptError.InvalidSignature();
    }

    return mk.decrypt(msg.cipher_text);
  }

  /**
   * @param msg {message.CipherMessage}
   * @returns {Array<session.ChainKey>|session.MessageKeys}
   */
  stage_message_keys(msg) {
    TypeUtil.assert_is_instance(CipherMessage, msg);

    const num = msg.counter - this.chain_key.idx;
    if (num > RecvChain.MAX_COUNTER_GAP) {
      throw new DecryptError.TooDistantFuture();
    }

    let keys = [];
    let chk = this.chain_key;

    for (let i = 0; i <= num - 1; i++) {
      keys.push(chk.message_keys());
      chk = chk.next();
    }

    const mk = chk.message_keys();
    return [chk, mk, keys];
  }

  /** @param keys {Array<session.MessageKeys>} */
  commit_message_keys(keys) {
    TypeUtil.assert_is_instance(Array, keys);
    keys.map((k) => TypeUtil.assert_is_instance(MessageKeys, k));

    if (keys.length > RecvChain.MAX_COUNTER_GAP) {
      throw new ProteusError('More keys than MAX_COUNTER_GAP');
    }

    const excess = this.message_keys.length + keys.length - RecvChain.MAX_COUNTER_GAP;

    for (let i = 0; i <= excess - 1; i++) {
      this.message_keys.shift();
    }

    keys.map((k) => this.message_keys.push(k));

    if (keys.length > RecvChain.MAX_COUNTER_GAP) {
      throw new ProteusError('Skipped keys greater than MAX_COUNTER_GAP');
    }
  }

  /**
   * @param e {CBOR.Encoder}
   * @returns {Array<CBOR.Encoder>}
   */
  encode(e) {
    e.object(3);
    e.u8(0);
    this.chain_key.encode(e);
    e.u8(1);
    this.ratchet_key.encode(e);

    e.u8(2);
    e.array(this.message_keys.length);
    return this.message_keys.map((k) => k.encode(e));
  }

  /**
   * @param d {CBOR.Decoder}
   * @returns {session.RecvChain}
   */
  static decode(d) {
    TypeUtil.assert_is_instance(CBOR.Decoder, d);

    const self = ClassUtil.new_instance(RecvChain);

    const nprops = d.object();
    for (let i = 0; i <= nprops - 1; i++) {
      switch (d.u8()) {
        case 0:
          self.chain_key = ChainKey.decode(d);
          break;
        case 1:
          self.ratchet_key = PublicKey.decode(d);
          break;
        case 2:
          self.message_keys = [];

          let len = d.array();
          while (len--) {
            self.message_keys.push(MessageKeys.decode(d));
          }
          break;

        default:
          d.skip();
      }
    }

    TypeUtil.assert_is_instance(ChainKey, self.chain_key);
    TypeUtil.assert_is_instance(PublicKey, self.ratchet_key);
    TypeUtil.assert_is_instance(Array, self.message_keys);

    return self;
  }
}

/** @type {number} */
RecvChain.MAX_COUNTER_GAP = 1000;

module.exports = RecvChain;
