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

describe 'PreKey', ->
  it 'should generate new PreKeys', ->
    pk = Proteus.keys.PreKey.new 0
    pk = Proteus.keys.PreKey.last_resort()
    assert(pk.key_id is Proteus.keys.PreKey.MAX_PREKEY_ID)

  it 'should reject invalid PreKey IDs', ->
    assert.throws(-> Proteus.keys.PreKey.new(undefined))
    assert.throws(-> Proteus.keys.PreKey.new("foo"))
    assert.throws(-> Proteus.keys.PreKey.new(-1))
    assert.throws(-> Proteus.keys.PreKey.new(65537))
    assert.throws(-> Proteus.keys.PreKey.new(4242.42))

  it 'should serialise and deserialise correctly', ->
    pk = Proteus.keys.PreKey.new 0
    pk_bytes = pk.serialise()
    pk_copy = Proteus.keys.PreKey.deserialise pk_bytes

    assert(pk_copy.version is pk.version)
    assert(pk_copy.key_id is pk.key_id)
    assert(pk_copy.key_pair.public_key.fingerprint() is pk.key_pair.public_key.fingerprint())

    assert(sodium.to_hex(new Uint8Array pk_bytes) is sodium.to_hex(new Uint8Array pk_copy.serialise()))
