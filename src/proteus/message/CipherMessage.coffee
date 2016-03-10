# Wire
# Copyright (C) 2016 Wire Swiss GmbH
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

Message = require './Message'
SessionTag = require './SessionTag'

module.exports = class CipherMessage extends Message
  constructor: ->
    throw new DontCallConstructor @

  @new: (session_tag, counter, prev_counter, ratchet_key, cipher_text) ->
    TypeUtil.assert_is_instance SessionTag, session_tag
    TypeUtil.assert_is_integer counter
    TypeUtil.assert_is_integer prev_counter
    TypeUtil.assert_is_instance PublicKey, ratchet_key
    TypeUtil.assert_is_instance Uint8Array, cipher_text

    cm = ClassUtil.new_instance CipherMessage

    cm.session_tag = session_tag
    cm.counter = counter
    cm.prev_counter = prev_counter
    cm.ratchet_key = ratchet_key
    cm.cipher_text = cipher_text

    Object.freeze cm
    return cm

  encode: (e) ->
    e.object 5
    e.u8 0; @session_tag.encode e
    e.u8 1; e.u32 @counter
    e.u8 2; e.u32 @prev_counter
    e.u8 3; @ratchet_key.encode e
    e.u8 4; e.bytes @cipher_text

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    session_tag  = null
    counter      = null
    prev_counter = null
    ratchet_key  = null
    cipher_text  = null

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then session_tag  = SessionTag.decode d
        when 1 then counter      = d.u32()
        when 2 then prev_counter = d.u32()
        when 3 then ratchet_key  = PublicKey.decode d
        when 4 then cipher_text  = new Uint8Array d.bytes()
        else d.skip()

    return CipherMessage.new session_tag, counter, prev_counter, ratchet_key, cipher_text
