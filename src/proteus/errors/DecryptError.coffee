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

ProteusError = require './ProteusError'

class DecryptError extends ProteusError
  constructor: (@message = 'Unknown decryption error') ->

class DecryptError.RemoteIdentityChanged extends DecryptError
  constructor: (@message = 'Remote identity changed') ->

class DecryptError.InvalidSignature extends DecryptError
  constructor: (@message = 'Invalid signature') ->

class DecryptError.InvalidMessage extends DecryptError
  constructor: (@message = 'Invalid message') ->

class DecryptError.DuplicateMessage extends DecryptError
  constructor: (@message = 'Duplicate message') ->

class DecryptError.TooDistantFuture extends DecryptError
  constructor: (@message = 'Message is from too distant in the future') ->

class DecryptError.OutdatedMessage extends DecryptError
  constructor: (@message = 'Outdated message') ->

class DecryptError.PrekeyNotFound extends DecryptError
  constructor: (@message = 'Pre-key not found') ->

module.exports = DecryptError
