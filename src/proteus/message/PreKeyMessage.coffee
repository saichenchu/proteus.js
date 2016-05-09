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

PublicKey = require '../keys/PublicKey'
IdentityKey = require '../keys/IdentityKey'

Message = require './Message'
CipherMessage = require './CipherMessage'

module.exports = class PreKeyMessage extends Message
  constructor: ->
    throw new DontCallConstructor @

  @new: (prekey_id, base_key, identity_key, message) ->
    TypeUtil.assert_is_integer prekey_id
    TypeUtil.assert_is_instance PublicKey, base_key
    TypeUtil.assert_is_instance IdentityKey, identity_key
    TypeUtil.assert_is_instance CipherMessage, message

    pkm = ClassUtil.new_instance PreKeyMessage

    pkm.prekey_id = prekey_id
    pkm.base_key = base_key
    pkm.identity_key = identity_key
    pkm.message = message

    Object.freeze pkm
    return pkm

  encode: (e) ->
    e.object 4
    e.u8 0; e.u16 @prekey_id
    e.u8 1; @base_key.encode e
    e.u8 2; @identity_key.encode e
    e.u8 3; @message.encode e

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    prekey_id    = null
    base_key     = null
    identity_key = null
    message      = null

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then prekey_id    = d.u16()
        when 1 then base_key     = PublicKey.decode d
        when 2 then identity_key = IdentityKey.decode d
        when 3 then message      = CipherMessage.decode d
        else d.skip()

    # checks for missing variables happens in constructor
    return PreKeyMessage.new prekey_id, base_key, identity_key, message
