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

CBOR = require 'cbor-codec'
sodium = require 'libsodium'

DontCallConstructor = require '../errors/DontCallConstructor'
ClassUtil = require '../util/ClassUtil'
TypeUtil = require '../util/TypeUtil'

module.exports = class MacKey
  constructor: ->
    throw new DontCallConstructor @

  ###
  key: mac::Key
  @param key [Uint8Array] Mac Key in byte array format generated by derived secrets
  ###
  @new: (key) ->
    TypeUtil.assert_is_instance Uint8Array, key

    mk = ClassUtil.new_instance MacKey
    mk.key = key
    return mk

  ###
  Hash-based message authentication code
  ###
  sign: (msg) ->
    return sodium.crypto_auth_hmacsha256(msg, @key)

  verify: (signature, msg) ->
    return sodium.crypto_auth_hmacsha256_verify(signature, msg, @key)

  encode: (e)->
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

    return MacKey.new key_bytes
