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

TypeUtil = require '../util/TypeUtil'
ProteusError = require '../errors/ProteusError'

module.exports = do ->
  ###
  Concatenates array buffers (usually 8-bit unsigned).
  ###

  concatenate_array_buffers: (buffers) ->
    TypeUtil.assert_is_instance Array, buffers

    return buffers.reduce (a, b) ->
      buf = new a.constructor (a.byteLength + b.byteLength)
      buf.set a, 0
      buf.set b, a.byteLength
      return buf

  assert_is_not_zeroes: (array) ->
    only_zeroes = true
    for val in array
      if val > 0
        only_zeroes = false
        break

    if only_zeroes
      throw new ProteusError 'Array consists only of zeroes.'
