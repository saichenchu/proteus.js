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

module.exports = do ->
  ###
  Concatenates array buffers (usually 8-bit unsigned).
  ###
  concatenate_array_buffers: ->
    args = Array.prototype.slice.call arguments
    return_buffer = args[0]

    if args.length > 1
      first_buffer = args.shift()
      concatenated_buffer = undefined
      for second_buffer in args
        concatenated_buffer = new first_buffer.constructor first_buffer.byteLength + second_buffer.byteLength
        concatenated_buffer.set first_buffer, 0
        concatenated_buffer.set second_buffer, first_buffer.byteLength
        first_buffer = concatenated_buffer
      return_buffer = concatenated_buffer

    return return_buffer

  array_buffer_to_string: (buffer) ->
    return String.fromCharCode.apply null, buffer

  ###
  @see https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String?hl=en
  ###
  string_to_array_buffer: (str) ->
    array_buffer = new ArrayBuffer(str.length * 2)
    # 2 bytes for each char
    bufView = new Uint16Array(array_buffer)
    i = 0
    strLen = str.length
    while i < strLen
      bufView[i] = str.charCodeAt(i)
      i++
    return array_buffer

  string_to_byte_array: (string) ->
    byte_array = []

    for index of string
      byte_array.push string.charCodeAt index

    return byte_array

  string_to_hex: (input) ->
    str = ''
    i = 0
    tmp_len = input.length
    c = undefined
    while i < tmp_len
      c = input.charCodeAt(i)
      str += c.toString(16)
      i += 1
    str

  byte_array_to_hex: (bytes) ->
    hex = []
    i = 0
    while i < bytes.length
      hex.push (bytes[i] >>> 4).toString(16)
      hex.push (bytes[i] & 0xF).toString(16)
      i++
    hex.join ''

  hex_to_byte_array: (hex) ->
    bytes = []
    c = 0
    while c < hex.length
      bytes.push parseInt(hex.substr(c, 2), 16)
      c += 2
    bytes

  byte_array_to_bit_array: (byte_array) ->
    bit_array_to_partial_word = (len, x, _end) ->
      if len == 32
        return x
      (if _end then x | 0 else x << 32 - len) + len * 0x10000000000

    out = []
    i = undefined
    tmp = 0
    i = 0
    while i < byte_array.length
      tmp = tmp << 8 | byte_array[i]
      if (i & 3) == 3
        out.push tmp
        tmp = 0
      i++
    if i & 3
      out.push bit_array_to_partial_word(8 * (i & 3), tmp)
    out

