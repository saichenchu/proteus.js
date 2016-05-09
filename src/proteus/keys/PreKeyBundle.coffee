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

IdentityKeyPair = require './IdentityKeyPair'
IdentityKey = require './IdentityKey'
PreKeyAuth = require './PreKeyAuth'
PublicKey = require './PublicKey'
PreKey = require './PreKey'

module.exports = class PreKeyBundle
  constructor: ->
    throw new DontCallConstructor @

  ###
  @param identity_key [Proteus.keys.IdentityKey]
  @param prekey [Proteus.keys.PreKey]
  ###
  @new: (identity_key, prekey) ->
    TypeUtil.assert_is_instance IdentityKey, identity_key
    TypeUtil.assert_is_instance PreKey, prekey

    bundle = ClassUtil.new_instance PreKeyBundle

    bundle.version = 1
    bundle.prekey_id = prekey.key_id
    bundle.public_key = prekey.key_pair.public_key
    bundle.identity_key = identity_key
    bundle.signature = null

    return bundle

  @signed: (identity_pair, prekey) ->
    TypeUtil.assert_is_instance IdentityKeyPair, identity_pair
    TypeUtil.assert_is_instance PreKey, prekey

    ratchet_key = prekey.key_pair.public_key
    signature = identity_pair.secret_key.sign(ratchet_key.pub_edward)

    bundle = ClassUtil.new_instance PreKeyBundle

    bundle.version = 1
    bundle.prekey_id = prekey.key_id
    bundle.public_key = ratchet_key
    bundle.identity_key = identity_pair.public_key
    bundle.signature = signature

    return bundle

  verify: ->
    if !@signature
      return PreKeyAuth.UNKNOWN

    if @identity_key.public_key.verify(@signature, @public_key.pub_edward)
      return PreKeyAuth.VALID
    return PreKeyAuth.INVALID

  serialise: ->
    e = new CBOR.Encoder()
    @encode e
    return e.get_buffer()

  @deserialise: (buf) ->
    TypeUtil.assert_is_instance ArrayBuffer, buf
    return PreKeyBundle.decode new CBOR.Decoder buf

  encode: (e) ->
    TypeUtil.assert_is_instance CBOR.Encoder, e

    e.object 5
    e.u8 0; e.u8 @version
    e.u8 1; e.u16 @prekey_id
    e.u8 2; @public_key.encode e
    e.u8 3; @identity_key.encode e

    e.u8 4
    if !@signature
      e.null()
    else
      e.bytes @signature

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    self = ClassUtil.new_instance PreKeyBundle

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then self.version      = d.u8()
        when 1 then self.prekey_id    = d.u16()
        when 2 then self.public_key   = PublicKey.decode d
        when 3 then self.identity_key = IdentityKey.decode d
        when 4 then self.signature    = d.optional(-> new Uint8Array d.bytes())
        else d.skip()

    TypeUtil.assert_is_integer self.version
    TypeUtil.assert_is_integer self.prekey_id
    TypeUtil.assert_is_instance PublicKey, self.public_key
    TypeUtil.assert_is_instance IdentityKey, self.identity_key

    return self
