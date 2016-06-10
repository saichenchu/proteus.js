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

class TestStore extends Proteus.session.PreKeyStore
  constructor: (@prekeys) ->

  get_prekey: (prekey_id) ->
    return @prekeys[prekey_id]

  remove: (prekey_id) ->
    delete @prekeys[prekey_id]

assert_init_from_message = (ident, store, msg, expected) ->
  [bob, msg] = Proteus.session.Session.init_from_message ident, store, msg
  assert.strictEqual(sodium.to_string(msg), expected)
  return bob

assert_decrypt = (expected, actual) ->
  assert.strictEqual(expected, sodium.to_string(actual))

assert_prev_count = (session, expected) ->
  assert.strictEqual(expected, session.session_states[session.session_tag].state.prev_counter)

assert_serialise_deserialise = (local_identity, session) ->
  bytes = session.serialise()

  deser = Proteus.session.Session.deserialise local_identity, bytes
  deser_bytes = deser.serialise()

  assert.deepEqual(
    sodium.to_hex(new Uint8Array bytes),
    sodium.to_hex(new Uint8Array deser_bytes))

describe 'Session', ->
  it 'can be serialised and deserialised to/from CBOR', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    assert(alice.session_states[alice.session_tag].state.recv_chains.length is 1)

    assert_serialise_deserialise alice_ident, alice

  it 'encrypts and decrypts messsages', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    assert(alice.session_states[alice.session_tag].state.recv_chains.length is 1)

    hello_bob = alice.encrypt 'Hello Bob!'
    hello_bob_delayed = alice.encrypt 'Hello delay!'
    assert(Object.keys(alice.session_states).length is 1)
    assert(alice.session_states[alice.session_tag].state.recv_chains.length is 1)

    bob = assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'
    assert(Object.keys(bob.session_states).length is 1)
    assert(bob.session_states[bob.session_tag].state.recv_chains.length is 1)

    hello_alice = bob.encrypt 'Hello Alice!'

    assert_decrypt 'Hello Alice!', alice.decrypt(alice_store, hello_alice)
    assert(alice.pending_prekey is null)
    assert(alice.session_states[alice.session_tag].state.recv_chains.length is 2)
    assert(alice.remote_identity.fingerprint() is bob.local_identity.public_key.fingerprint())

    ping_bob_1 = alice.encrypt 'Ping1!'
    ping_bob_2 = alice.encrypt 'Ping2!'
    assert_prev_count alice, 2

    assert(ping_bob_1.message instanceof Proteus.message.CipherMessage)
    assert(ping_bob_2.message instanceof Proteus.message.CipherMessage)

    assert_decrypt 'Ping1!', bob.decrypt bob_store, ping_bob_1
    assert(bob.session_states[bob.session_tag].state.recv_chains.length is 2)
    assert_decrypt 'Ping2!', bob.decrypt bob_store, ping_bob_2
    assert(bob.session_states[bob.session_tag].state.recv_chains.length is 2)

    pong_alice = bob.encrypt 'Pong!'
    assert_prev_count bob, 1

    assert_decrypt 'Pong!', alice.decrypt alice_store, pong_alice
    assert(alice.session_states[alice.session_tag].state.recv_chains.length is 3)
    assert_prev_count alice, 2

    assert_decrypt 'Hello delay!', bob.decrypt bob_store, hello_bob_delayed
    assert(bob.session_states[bob.session_tag].state.recv_chains.length is 2)
    assert_prev_count bob, 1

    assert_serialise_deserialise alice_ident, alice
    assert_serialise_deserialise bob_ident, bob

  it 'should limit the number of receive chains', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    hello_bob = alice.encrypt 'Hello Bob!'

    bob = assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    assert(alice.session_states[alice.session_tag].state.recv_chains.length is 1)
    assert(bob.session_states[bob.session_tag].state.recv_chains.length is 1)

    for _ in [0..(Proteus.session.Session.MAX_RECV_CHAINS * 2)]
      assert_decrypt 'ping', alice.decrypt alice_store, bob.encrypt 'ping'
      assert_decrypt 'pong', bob.decrypt bob_store, alice.encrypt 'pong'

      assert.isAtMost(alice.session_states[alice.session_tag].state.recv_chains.length,
        Proteus.session.Session.MAX_RECV_CHAINS)
      assert.isAtMost(bob.session_states[bob.session_tag].state.recv_chains.length,
        Proteus.session.Session.MAX_RECV_CHAINS)

  it 'should handle a counter mismatch', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    hello_bob = alice.encrypt 'Hello Bob!'

    bob = assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    cipher_texts =
      hello1: bob.encrypt 'Hello1'
      hello2: bob.encrypt 'Hello2'
      hello3: bob.encrypt 'Hello3'
      hello4: bob.encrypt 'Hello4'
      hello5: bob.encrypt 'Hello5'

    assert_decrypt 'Hello2', alice.decrypt alice_store, cipher_texts.hello2
    assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 1)

    assert_serialise_deserialise alice_ident, alice

    assert_decrypt 'Hello1', alice.decrypt alice_store, cipher_texts.hello1
    assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 0)

    assert_decrypt 'Hello3', alice.decrypt alice_store, cipher_texts.hello3
    assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 0)

    assert_decrypt 'Hello5', alice.decrypt alice_store, cipher_texts.hello5
    assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 1)

    assert_decrypt 'Hello4', alice.decrypt alice_store, cipher_texts.hello4
    assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 0)

    for _, message of cipher_texts
      malfunction = -> alice.decrypt alice_store, message
      assert.throws malfunction, Proteus.errors.DecryptError.DuplicateMessage

    assert_serialise_deserialise alice_ident, alice
    assert_serialise_deserialise bob_ident, bob

  it 'should handle multiple prekey messages', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    bob_store = new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle

    hello_bob1 = alice.encrypt 'Hello Bob1!'
    hello_bob2 = alice.encrypt 'Hello Bob2!'
    hello_bob3 = alice.encrypt 'Hello Bob3!'

    bob = assert_init_from_message bob_ident, bob_store, hello_bob1, 'Hello Bob1!'
    assert(Object.keys(bob.session_states).length is 1)
    assert_decrypt 'Hello Bob2!', bob.decrypt bob_store, hello_bob2
    assert(Object.keys(bob.session_states).length is 1)
    assert_decrypt 'Hello Bob3!', bob.decrypt bob_store, hello_bob3
    assert(Object.keys(bob.session_states).length is 1)

    assert_serialise_deserialise alice_ident, alice
    assert_serialise_deserialise bob_ident, bob

  it 'should handle simultaneous prekey messages', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice_prekey = alice_store.prekeys[0]
    alice_bundle = Proteus.keys.PreKeyBundle.new alice_ident.public_key, alice_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    hello_bob = alice.encrypt 'Hello Bob!'

    bob = Proteus.session.Session.init_from_prekey bob_ident, alice_bundle
    hello_alice = bob.encrypt 'Hello Alice!'

    assert(alice.session_tag.toString() isnt bob.session_tag.toString())

    assert_decrypt 'Hello Bob!', bob.decrypt bob_store, hello_bob
    assert(Object.keys(bob.session_states).length is 2)

    assert_decrypt 'Hello Alice!', alice.decrypt alice_store, hello_alice
    assert(Object.keys(alice.session_states).length is 2)

    greet_bob = alice.encrypt 'That was fast!'
    assert_decrypt 'That was fast!', bob.decrypt bob_store, greet_bob

    answer_alice = bob.encrypt ':-)'
    assert_decrypt ':-)', alice.decrypt alice_store, answer_alice

    assert(alice.session_tag.toString() is bob.session_tag.toString())

    assert_serialise_deserialise alice_ident, alice
    assert_serialise_deserialise bob_ident, bob

  it 'should handle simultaneous repeated messages', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice_prekey = alice_store.prekeys[0]
    alice_bundle = Proteus.keys.PreKeyBundle.new alice_ident.public_key, alice_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    hello_bob = alice.encrypt 'Hello Bob!'

    bob = Proteus.session.Session.init_from_prekey bob_ident, alice_bundle
    hello_alice = bob.encrypt 'Hello Alice!'

    assert(alice.session_tag.toString() isnt bob.session_tag.toString())

    assert_decrypt 'Hello Bob!', bob.decrypt bob_store, hello_bob
    assert_decrypt 'Hello Alice!', alice.decrypt alice_store, hello_alice

    echo_bob1 = alice.encrypt 'Echo Bob1!'
    echo_alice1 = bob.encrypt 'Echo Alice1!'

    assert_decrypt 'Echo Bob1!', bob.decrypt bob_store, echo_bob1
    assert(Object.keys(bob.session_states).length is 2)

    assert_decrypt 'Echo Alice1!', alice.decrypt alice_store, echo_alice1
    assert(Object.keys(alice.session_states).length is 2)

    assert(alice.session_tag.toString() isnt bob.session_tag.toString())

    echo_bob2 = alice.encrypt 'Echo Bob2!'
    echo_alice2 = bob.encrypt 'Echo Alice2!'

    assert_decrypt 'Echo Bob2!', bob.decrypt bob_store, echo_bob2
    assert(Object.keys(bob.session_states).length is 2)

    assert_decrypt 'Echo Alice2!', alice.decrypt alice_store, echo_alice2
    assert(Object.keys(alice.session_states).length is 2)

    assert(alice.session_tag.toString() isnt bob.session_tag.toString())

    stop_bob = alice.encrypt 'Stop it!'
    assert_decrypt 'Stop it!', bob.decrypt bob_store, stop_bob

    answer_alice = bob.encrypt 'OK'
    assert_decrypt 'OK', alice.decrypt alice_store, answer_alice

    assert(alice.session_tag.toString() is bob.session_tag.toString())

    assert_serialise_deserialise alice_ident, alice
    assert_serialise_deserialise bob_ident, bob

  it 'should handle mass communication', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    hello_bob = alice.encrypt 'Hello Bob!'

    bob = assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    # XXX: need to serialize/deserialize to/from CBOR here
    messages = [0...999].map(-> bob.encrypt 'Hello Alice!')
    messages.map((m) -> assert_decrypt 'Hello Alice!', alice.decrypt alice_store, m)

    assert_serialise_deserialise alice_ident, alice
    assert_serialise_deserialise bob_ident, bob

  it 'should fail retry init from message', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    bob_store = new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    hello_bob = alice.encrypt 'Hello Bob!'

    bob = assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    assert.throws((-> Proteus.session.Session.init_from_message bob_ident, bob_store, hello_bob),
      Proteus.errors.DecryptError.PrekeyNotFound)

  it 'pathological case', ->
    @timeout 0

    num_alices = 32

    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    bob_store = new TestStore Proteus.keys.PreKey.generate_prekeys 0, num_alices

    alices = bob_store.prekeys.map((pk) ->
      bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, pk
      return Proteus.session.Session.init_from_prekey alice_ident, bundle)

    assert(alices.length is num_alices)

    hello_bob = alices[0].encrypt 'Hello Bob!'
    bob = assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    alices.map (a) ->
      # XXX: rust code uses 0..900, but that takes too long for JS to run and the
      #      test suite times out
      for _ in [0..900]
        a.encrypt 'hello'

      hello_bob = a.encrypt 'Hello Bob!'
      assert_decrypt 'Hello Bob!', bob.decrypt bob_store, hello_bob

    assert(Object.keys(bob.session_states).length is num_alices)

    alices.map (a) ->
      assert_decrypt 'Hello Bob!', bob.decrypt bob_store, a.encrypt 'Hello Bob!'

    return

  it 'skipped message keys', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    hello_bob = alice.encrypt 'Hello Bob!'

    do ->
      s = alice.session_states[alice.session_tag].state
      assert(s.recv_chains.length is 1)
      assert(s.recv_chains[0].chain_key.idx is 0)
      assert(s.send_chain.chain_key.idx is 1)
      assert(s.recv_chains[0].message_keys.length is 0)

    bob = assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    do ->
      # Normal exchange. Bob has created a new receive chain without skipped message keys.

      s = bob.session_states[bob.session_tag].state
      assert(s.recv_chains.length is 1)
      assert(s.recv_chains[0].chain_key.idx is 1)
      assert(s.send_chain.chain_key.idx is 0)
      assert(s.recv_chains[0].message_keys.length is 0)

    hello_alice0 = bob.encrypt 'Hello0'
    bob.encrypt 'Hello1'
    hello_alice2 = bob.encrypt 'Hello2'

    alice.decrypt alice_store, hello_alice2

    do ->
      # Alice has two skipped message keys in her new receive chain.

      s = alice.session_states[alice.session_tag].state
      assert(s.recv_chains.length is 2)
      assert(s.recv_chains[0].chain_key.idx is 3)
      assert(s.send_chain.chain_key.idx is 0)
      assert(s.recv_chains[0].message_keys.length is 2)
      assert(s.recv_chains[0].message_keys[0].counter is 0)
      assert(s.recv_chains[0].message_keys[1].counter is 1)

    hello_bob0 = alice.encrypt 'Hello0'
    assert_decrypt 'Hello0', bob.decrypt bob_store, hello_bob0

    do ->
      # For Bob everything is normal still. A new message from Alice means a
      # new receive chain has been created and again no skipped message keys.

      s = bob.session_states[bob.session_tag].state
      assert(s.recv_chains.length is 2)
      assert(s.recv_chains[0].chain_key.idx is 1)
      assert(s.send_chain.chain_key.idx is 0)
      assert(s.recv_chains[0].message_keys.length is 0)

    assert_decrypt 'Hello0', alice.decrypt alice_store, hello_alice0

    do ->
      # Alice received the first of the two missing messages. Therefore
      # only one message key is still skipped (counter value = 1).

      s = alice.session_states[alice.session_tag].state
      assert(s.recv_chains.length is 2)
      assert(s.recv_chains[0].message_keys.length is 1)
      assert(s.recv_chains[0].message_keys[0].counter is 1)

    hello_again0 = bob.encrypt 'Again0'
    hello_again1 = bob.encrypt 'Again1'

    assert_decrypt 'Again1', alice.decrypt alice_store, hello_again1

    do ->
      # Alice received the first of the two missing messages. Therefore
      # only one message key is still skipped (counter value = 1).

      s = alice.session_states[alice.session_tag].state
      assert(s.recv_chains.length is 3)
      assert(s.recv_chains[0].message_keys.length is 1)
      assert(s.recv_chains[1].message_keys.length is 1)
      assert(s.recv_chains[0].message_keys[0].counter is 0)
      assert(s.recv_chains[1].message_keys[0].counter is 1)

    assert_decrypt 'Again0', alice.decrypt alice_store, hello_again0

  it 'replaced prekeys', ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [bob_store1, bob_store2] = [0..2].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 1)

    bob_prekey = bob_store1.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    hello_bob1 = alice.encrypt 'Hello Bob1!'

    bob = assert_init_from_message bob_ident, bob_store1, hello_bob1, 'Hello Bob1!'
    assert(Object.keys(bob.session_states).length is 1)

    hello_bob2 = alice.encrypt 'Hello Bob2!'
    assert_decrypt 'Hello Bob2!', bob.decrypt bob_store1, hello_bob2
    assert(Object.keys(bob.session_states).length is 1)

    hello_bob3 = alice.encrypt 'Hello Bob3!'
    assert_decrypt 'Hello Bob3!', bob.decrypt bob_store2, hello_bob3
    assert(Object.keys(bob.session_states).length is 1)

  it 'max counter gap', ->
    @timeout 0

    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())

    keys = []
    keys[Proteus.keys.PreKey.MAX_PREKEY_ID] = Proteus.keys.PreKey.last_resort()
    bob_store = new TestStore keys

    bob_prekey = bob_store.prekeys[Proteus.keys.PreKey.MAX_PREKEY_ID]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    hello_bob1 = alice.encrypt 'Hello Bob1!'

    bob = assert_init_from_message bob_ident, bob_store, hello_bob1, 'Hello Bob1!'
    assert(Object.keys(bob.session_states).length is 1)

    for i in [0..1001]
      hello_bob2 = alice.encrypt 'Hello Bob2!'
      assert_decrypt 'Hello Bob2!', bob.decrypt bob_store, hello_bob2
      assert.strictEqual(Object.keys(bob.session_states).length, 1)

    return
