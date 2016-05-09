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
TypeUtil = require '../util/TypeUtil'

DecodeError = require '../errors/DecodeError'

module.exports = class Message
  constructor: ->
    throw new DontCallConstructor @

  serialise: ->
    e = new CBOR.Encoder()

    switch
      when @ instanceof CipherMessage then e.u8 1
      when @ instanceof PreKeyMessage then e.u8 2
      else throw new TypeError 'Unexpected message type'

    @encode e
    return e.get_buffer()

  @deserialise: (buf) ->
    TypeUtil.assert_is_instance ArrayBuffer, buf

    d = new CBOR.Decoder buf

    return switch d.u8()
      when 1 then CipherMessage.decode d
      when 2 then PreKeyMessage.decode d
      else throw new DecodeError.InvalidType 'Unrecognised message type'

# these require lines have to come after the Message definition because otherwise
# it creates a circular dependency with the message subtypes
CipherMessage = require './CipherMessage'
PreKeyMessage = require './PreKeyMessage'
