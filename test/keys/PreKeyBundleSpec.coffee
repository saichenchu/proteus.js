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

describe 'PreKeyBundle', ->
  it 'should create a bundle', ->
    id_pair = Proteus.keys.IdentityKeyPair.new()
    prekey = Proteus.keys.PreKey.new 1
    bundle = Proteus.keys.PreKeyBundle.new id_pair.public_key, prekey

    assert(bundle.verify() is Proteus.keys.PreKeyAuth.UNKNOWN)

  it 'should create a valid signed bundle', ->
    id_pair = Proteus.keys.IdentityKeyPair.new()
    prekey = Proteus.keys.PreKey.new 1
    bundle = Proteus.keys.PreKeyBundle.signed id_pair, prekey

    assert(bundle.verify() is Proteus.keys.PreKeyAuth.VALID)

  it 'should serialise and deserialise a unsigned bundle', ->
    id_pair = Proteus.keys.IdentityKeyPair.new()
    prekey = Proteus.keys.PreKey.new 1
    bundle = Proteus.keys.PreKeyBundle.new id_pair.public_key, prekey

    assert(bundle.verify() is Proteus.keys.PreKeyAuth.UNKNOWN)

    pkb_bytes = bundle.serialise()
    pkb_copy  = Proteus.keys.PreKeyBundle.deserialise pkb_bytes

    assert(pkb_copy.verify() is Proteus.keys.PreKeyAuth.UNKNOWN)

    assert(pkb_copy.version is bundle.version)
    assert(pkb_copy.prekey_id is bundle.prekey_id)
    assert(pkb_copy.public_key.fingerprint() is bundle.public_key.fingerprint())
    assert(pkb_copy.identity_key.fingerprint() is bundle.identity_key.fingerprint())
    assert(pkb_copy.signature is bundle.signature)

    assert(sodium.to_hex(new Uint8Array pkb_bytes) is sodium.to_hex(new Uint8Array pkb_copy.serialise()))

  it 'should serialise and deserialise a signed bundle', ->
    id_pair = Proteus.keys.IdentityKeyPair.new()
    prekey = Proteus.keys.PreKey.new 1
    bundle = Proteus.keys.PreKeyBundle.signed id_pair, prekey

    assert(bundle.verify() is Proteus.keys.PreKeyAuth.VALID)

    pkb_bytes = bundle.serialise()
    pkb_copy  = Proteus.keys.PreKeyBundle.deserialise pkb_bytes

    assert(pkb_copy.verify() is Proteus.keys.PreKeyAuth.VALID)

    assert(pkb_copy.version is bundle.version)
    assert(pkb_copy.prekey_id is bundle.prekey_id)
    assert(pkb_copy.public_key.fingerprint() is bundle.public_key.fingerprint())
    assert(pkb_copy.identity_key.fingerprint() is bundle.identity_key.fingerprint())
    assert(sodium.to_hex(pkb_copy.signature) is sodium.to_hex(bundle.signature))

    assert(sodium.to_hex(new Uint8Array pkb_bytes) is sodium.to_hex(new Uint8Array pkb_copy.serialise()))
