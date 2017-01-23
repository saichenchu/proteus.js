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
chacha20 = require 'chacha20'
sodium = require 'libsodium-wrappers-sumo'

DontCallConstructor = require '../errors/DontCallConstructor'
ClassUtil = require '../util/ClassUtil'
TypeUtil = require '../util/TypeUtil'

module.exports = class CipherKey
  constructor: ->
    throw new DontCallConstructor @

  @new: (key) ->
    TypeUtil.assert_is_instance Uint8Array, key

    ck = ClassUtil.new_instance CipherKey
    ck.key = key
    return ck

  ###
  @param plaintext [String, Uint8Array, ArrayBuffer] The text to encrypt
  @param nonce [Uint8Array] Counter as nonce
  @return [Uint8Array] Encrypted payload
  ###
  encrypt: (plaintext, nonce) ->
    # @todo Re-validate if the ArrayBuffer check is needed (Prerequisite: Integration tests)
    if plaintext instanceof ArrayBuffer and plaintext.byteLength isnt undefined
      plaintext = new Uint8Array plaintext

    encrypted_buffer = chacha20.encrypt nonce.buffer, @key.buffer, new Buffer(plaintext)
    return new Uint8Array encrypted_buffer

  decrypt: (ciphertext, nonce) ->
    return @encrypt ciphertext, nonce

  encode: (e) ->
    e.object 1
    e.u8 0; e.bytes @key

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    key_bytes = null

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then key_bytes = new Uint8Array d.bytes()
        else d.skip()

    return CipherKey.new key_bytes
