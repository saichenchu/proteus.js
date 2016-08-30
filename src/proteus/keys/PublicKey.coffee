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

module.exports = class PublicKey
  constructor: ->
    throw new DontCallConstructor @

  @new: (pub_edward, pub_curve) ->
    TypeUtil.assert_is_instance Uint8Array, pub_edward
    TypeUtil.assert_is_instance Uint8Array, pub_curve

    pk = ClassUtil.new_instance PublicKey

    pk.pub_edward = pub_edward
    pk.pub_curve = pub_curve

    return pk

  ###
  This function can be used to verify a message signature.

  @param signature [Uint8Array] The signature to verify
  @param message [String, Uint8Array] The message from which the signature was computed.
  @return [bool] `true` if the signature is valid, `false` otherwise.
  ###
  verify: (signature, message) ->
    TypeUtil.assert_is_instance Uint8Array, signature
    return sodium.crypto_sign_verify_detached(signature, message, @pub_edward)

  fingerprint: ->
    return sodium.to_hex @pub_edward

  encode: (e) ->
    e.object 1
    e.u8 0; e.bytes @pub_edward

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    self = ClassUtil.new_instance PublicKey

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then self.pub_edward = new Uint8Array d.bytes()
        else d.skip()

    TypeUtil.assert_is_instance Uint8Array, self.pub_edward

    self.pub_curve = sodium.crypto_sign_ed25519_pk_to_curve25519 self.pub_edward
    return self
