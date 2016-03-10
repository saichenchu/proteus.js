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

DecodeError = require '../errors/DecodeError'
RandomUtil = require '../util/RandomUtil'

module.exports = class SessionTag
  constructor: ->
    throw new DontCallConstructor @

  @new: ->
    st = ClassUtil.new_instance SessionTag
    st.tag = RandomUtil.random_bytes 16
    return st

  toString: ->
    return sodium.to_hex @tag

  encode: (e) ->
    e.bytes @tag

  @decode: (d) ->
    TypeUtil.assert_is_instance CBOR.Decoder, d

    bytes = new Uint8Array d.bytes()
    if bytes.byteLength isnt 16
      throw DecodeError.InvalidArrayLen "SessionTag should be 16 bytes, not #{bytes.byteLength} bytes."

    st = ClassUtil.new_instance SessionTag
    st.tag = new Uint8Array bytes
    return st
