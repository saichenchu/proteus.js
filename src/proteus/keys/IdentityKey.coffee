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

PublicKey = require './PublicKey'

###
Construct a long-term identity key pair.

Every client has a long-term identity key pair.
Long-term identity keys are used to initialise “sessions” with other clients (triple DH).
###
module.exports = class IdentityKey
  constructor: ->
    throw new DontCallConstructor @

  @new: (public_key) ->
    TypeUtil.assert_is_instance PublicKey, public_key

    key = ClassUtil.new_instance IdentityKey
    key.public_key = public_key
    return key

  fingerprint: ->
    @public_key.fingerprint()

  toString: ->
    return sodium.to_hex @public_key

  encode: (e) ->
    e.object 1
    e.u8 0; @public_key.encode e

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    public_key = null

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then public_key = PublicKey.decode d
        else d.skip()

    return IdentityKey.new public_key
