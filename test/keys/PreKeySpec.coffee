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

describe 'PreKey', ->
  describe 'Generation', ->
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

    it 'generates ranges of PreKeys', ->
      prekeys = Proteus.keys.PreKey.generate_prekeys 0, 0
      assert.strictEqual prekeys.length, 0

      prekeys = Proteus.keys.PreKey.generate_prekeys 0, 1
      assert.strictEqual prekeys.length, 1
      assert(prekeys[0].key_id is 0)

      prekeys = Proteus.keys.PreKey.generate_prekeys 0, 10
      assert(prekeys.length is 10)
      assert(prekeys[0].key_id is 0)
      assert(prekeys[9].key_id is 9)

      prekeys = Proteus.keys.PreKey.generate_prekeys 3000, 10
      assert(prekeys.length is 10)
      assert(prekeys[0].key_id is 3000)
      assert(prekeys[9].key_id is 3009)

    it 'does not include the last resort pre key', ->
      prekeys = Proteus.keys.PreKey.generate_prekeys 65530, 10
      assert(prekeys.length is 10)
      assert(prekeys[0].key_id is 65530)
      assert(prekeys[1].key_id is 65531)
      assert(prekeys[2].key_id is 65532)
      assert(prekeys[3].key_id is 65533)
      assert(prekeys[4].key_id is 65534)
      assert(prekeys[5].key_id is 0)
      assert(prekeys[6].key_id is 1)
      assert(prekeys[7].key_id is 2)
      assert(prekeys[8].key_id is 3)
      assert(prekeys[9].key_id is 4)

      prekeys = Proteus.keys.PreKey.generate_prekeys Proteus.keys.PreKey.MAX_PREKEY_ID, 1
      assert.strictEqual prekeys.length, 1
      assert(prekeys[0].key_id is 0)

  describe 'Serialisation', ->
    it 'should serialise and deserialise correctly', ->
      pk = Proteus.keys.PreKey.new 0
      pk_bytes = pk.serialise()
      pk_copy = Proteus.keys.PreKey.deserialise pk_bytes

      assert(pk_copy.version is pk.version)
      assert(pk_copy.key_id is pk.key_id)
      assert(pk_copy.key_pair.public_key.fingerprint() is pk.key_pair.public_key.fingerprint())

      assert(sodium.to_hex(new Uint8Array pk_bytes) is sodium.to_hex(new Uint8Array pk_copy.serialise()))
