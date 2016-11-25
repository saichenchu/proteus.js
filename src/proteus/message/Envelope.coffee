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

Message = require './Message'

module.exports = class Envelope
  constructor: ->
    throw new DontCallConstructor @

  @new: (mac_key, message) ->
    TypeUtil.assert_is_instance MacKey, mac_key
    TypeUtil.assert_is_instance Message, message

    message_enc = new Uint8Array message.serialise()

    env = ClassUtil.new_instance Envelope

    env.version = 1
    env.mac = mac_key.sign message_enc
    env.message = message
    env._message_enc = message_enc

    Object.freeze env
    return env

  verify: (mac_key) ->
    TypeUtil.assert_is_instance MacKey, mac_key
    return mac_key.verify @mac, @_message_enc

  ###
  @return [ArrayBuffer] The serialized message envelope
  ###
  serialise: ->
    e = new CBOR.Encoder()
    @encode e
    return e.get_buffer()

  @deserialise: (buf) ->
    TypeUtil.assert_is_instance ArrayBuffer, buf

    d = new CBOR.Decoder buf
    return Envelope.decode d

  encode: (e) ->
    e.object 3
    e.u8 0; e.u8 @version

    e.u8 1
    e.object 1
    e.u8 0; e.bytes @mac

    e.u8 2; e.bytes @_message_enc

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    env = ClassUtil.new_instance Envelope

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then env.version = d.u8()
        when 1
          nprops_mac = d.object()
          for [0..(nprops_mac - 1)]
            switch d.u8()
              when 0 then env.mac = new Uint8Array d.bytes()
              else d.skip()

        when 2 then env._message_enc = new Uint8Array d.bytes()
        else d.skip()

    TypeUtil.assert_is_integer env.version
    TypeUtil.assert_is_instance Uint8Array, env.mac

    env.message = Message.deserialise env._message_enc.buffer

    Object.freeze env
    return env
