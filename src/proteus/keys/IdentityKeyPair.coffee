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

DontCallConstructor = require '../errors/DontCallConstructor'
ClassUtil = require '../util/ClassUtil'
TypeUtil = require '../util/TypeUtil'

IdentityKey = require './IdentityKey'
SecretKey = require './SecretKey'
KeyPair = require './KeyPair'

module.exports = class IdentityKeyPair
  constructor: ->
    throw new DontCallConstructor @

  @new: ->
    key_pair = KeyPair.new()

    ikp = ClassUtil.new_instance IdentityKeyPair
    ikp.version = 1
    ikp.secret_key = key_pair.secret_key
    ikp.public_key = IdentityKey.new key_pair.public_key

    return ikp

  serialise: ->
    e = new CBOR.Encoder()
    @encode e
    return e.get_buffer()

  @deserialise: (buf) ->
    TypeUtil.assert_is_instance ArrayBuffer, buf

    d = new CBOR.Decoder buf
    return IdentityKeyPair.decode d

  encode: (e) ->
    e.object 3
    e.u8 0; e.u8 @version
    e.u8 1; @secret_key.encode e
    e.u8 2; @public_key.encode e

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    self = ClassUtil.new_instance IdentityKeyPair

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then self.version = d.u8()
        when 1 then self.secret_key = SecretKey.decode d
        when 2 then self.public_key = IdentityKey.decode d
        else d.skip()

    TypeUtil.assert_is_integer self.version
    TypeUtil.assert_is_instance SecretKey, self.secret_key
    TypeUtil.assert_is_instance IdentityKey, self.public_key

    return self
