# Wire
# Copyright (C) 2016 Wire Swiss GmbH
# Based on libsignal-protocol-java by Open Whisper Systems
# https://github.com/WhisperSystems/libsignal-protocol-java
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

CBOR = require 'wire-webapp-cbor'

DontCallConstructor = require '../errors/DontCallConstructor'
ClassUtil = require '../util/ClassUtil'
TypeUtil = require '../util/TypeUtil'

MacKey = require '../derived/MacKey'
CipherKey = require '../derived/CipherKey'

module.exports = class MessageKeys
  constructor: ->
    throw new DontCallConstructor @

  @new: (cipher_key, mac_key, counter) ->
    TypeUtil.assert_is_instance CipherKey, cipher_key
    TypeUtil.assert_is_instance MacKey, mac_key
    TypeUtil.assert_is_integer counter

    mk = ClassUtil.new_instance MessageKeys
    mk.cipher_key = cipher_key
    mk.mac_key = mac_key
    mk.counter = counter
    return mk

  _counter_as_nonce: ->
    nonce = new ArrayBuffer 8
    new DataView(nonce).setUint32 0, @counter
    return new Uint8Array nonce

  encrypt: (plaintext) ->
    @cipher_key.encrypt plaintext, @_counter_as_nonce()

  decrypt: (ciphertext) ->
    @cipher_key.decrypt ciphertext, @_counter_as_nonce()

  encode: (e) ->
    e.object 3
    e.u8 0; @cipher_key.encode e
    e.u8 1; @mac_key.encode e
    e.u8 2; e.u32 @counter

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    self = ClassUtil.new_instance MessageKeys

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then self.cipher_key = CipherKey.decode d
        when 1 then self.mac_key    = MacKey.decode d
        when 2 then self.counter    = d.u32()
        else d.skip()

    TypeUtil.assert_is_instance CipherKey, self.cipher_key
    TypeUtil.assert_is_instance MacKey, self.mac_key
    TypeUtil.assert_is_integer self.counter

    return self
