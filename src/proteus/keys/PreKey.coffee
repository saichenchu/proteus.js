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

KeyPair = require './KeyPair'

###
Pre-generated (and regularly refreshed) pre-keys.
A Pre-Shared Key contains the public long-term identity and ephemeral handshake keys for the initial triple DH.
###
module.exports = class PreKey
  @MAX_PREKEY_ID: 0xFFFF

  constructor: ->
    throw new DontCallConstructor @

  ###
  @param pre_key_id [Integer]
  ###
  @new: (pre_key_id) ->
    TypeUtil.assert_is_integer pre_key_id

    if pre_key_id < 0 or pre_key_id > PreKey.MAX_PREKEY_ID
      throw new RangeError "Argument pre_key_id (#{pre_key_id}) must be between 0 (inclusive) and #{PreKey.MAX_PREKEY_ID} (inclusive)."

    pk = ClassUtil.new_instance PreKey

    pk.version = 1
    pk.key_id = pre_key_id
    pk.key_pair = KeyPair.new()

    return pk

  @last_resort: ->
    return PreKey.new PreKey.MAX_PREKEY_ID

  @generate_prekeys: (start, size) ->
    check_integer = (value) ->
      TypeUtil.assert_is_integer value

      if value < 0 or value > PreKey.MAX_PREKEY_ID
        throw new RangeError("Arguments must be between 0 (inclusive) and #{PreKey.MAX_PREKEY_ID} (inclusive).")

    check_integer start
    check_integer size

    return [] if size is 0

    return [0..(size - 1)].map((x) ->
      return PreKey.new (start + x) % PreKey.MAX_PREKEY_ID)

  serialise: ->
    e = new CBOR.Encoder()
    @encode e
    return e.get_buffer()

  @deserialise: (buf) ->
    TypeUtil.assert_is_instance ArrayBuffer, buf
    return PreKey.decode new CBOR.Decoder buf

  encode: (e) ->
    TypeUtil.assert_is_instance CBOR.Encoder, e

    e.object 3
    e.u8 0; e.u8 @version
    e.u8 1; e.u16 @key_id
    e.u8 2; @key_pair.encode e

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    self = ClassUtil.new_instance PreKey

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then self.version  = d.u8()
        when 1 then self.key_id   = d.u16()
        when 2 then self.key_pair = KeyPair.decode d
        else d.skip()

    TypeUtil.assert_is_integer self.version
    TypeUtil.assert_is_integer self.key_id
    TypeUtil.assert_is_instance KeyPair, self.key_pair

    return self
