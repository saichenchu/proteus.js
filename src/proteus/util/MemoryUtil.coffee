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

ProteusError = require '../errors/ProteusError'
sodium = require 'libsodium-wrappers-sumo'
TypeUtil = require '../util/TypeUtil'

module.exports = do ->
  zeroize: (object) ->
    if object instanceof Uint8Array
      sodium.memzero object
    else if object instanceof ArrayBuffer
      sodium.memzero new Uint8Array object
    else if typeof object is 'object'
      for key, val of object
        @zeroize val
