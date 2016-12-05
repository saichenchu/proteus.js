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
    return new Promise (resolve, reject) =>
      resolve @prekeys[prekey_id]

  remove: (prekey_id) ->
    return new Promise (resolve, reject) =>
      delete @prekeys[prekey_id]
      resolve()

assert_init_from_message = (ident, store, msg, expected) ->
  return new Promise (resolve, reject) ->
    Proteus.session.Session.init_from_message ident, store, msg
    .then (x) ->
      [s, msg] = x
      assert.strictEqual(sodium.to_string(msg), expected)
      resolve s

    .catch (e) ->
      reject e

assert_decrypt = (expected, p) ->
  return new Promise (resolve, reject) ->
    p.then (actual) ->
      assert.strictEqual(expected, sodium.to_string(actual))
      resolve()
    .catch (e) ->
      reject e

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

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (alice) ->
      assert(alice.session_states[alice.session_tag].state.recv_chains.length is 1)
      assert_serialise_deserialise alice_ident, alice

  it 'encrypts and decrypts messsages', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = null
    bob = null

    hello_bob = null
    hello_bob_delayed = null
    hello_alice = null
    ping_bob_1 = null
    ping_bob_2 = null
    pong_alice = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s

      assert(alice.session_states[alice.session_tag].state.recv_chains.length is 1)

      Promise.all(['Hello Bob!', 'Hello delay!'].map((x) -> alice.encrypt x))

    .then (msgs) ->
      [hello_bob, hello_bob_delayed] = msgs

      assert(Object.keys(alice.session_states).length is 1)
      assert(alice.session_states[alice.session_tag].state.recv_chains.length is 1)

      assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    .then (s) ->
      bob = s

      assert(Object.keys(bob.session_states).length is 1)
      assert(bob.session_states[bob.session_tag].state.recv_chains.length is 1)

      bob.encrypt 'Hello Alice!'

    .then (m) ->
      hello_alice = m
      assert_decrypt 'Hello Alice!', alice.decrypt(alice_store, hello_alice)

    .then ->
      assert(alice.pending_prekey is null)
      assert(alice.session_states[alice.session_tag].state.recv_chains.length is 2)
      assert(alice.remote_identity.fingerprint() is bob.local_identity.public_key.fingerprint())

      Promise.all(['Ping1!', 'Ping2!'].map((x) -> alice.encrypt x))

    .then (msgs) ->
      [ping_bob_1, ping_bob_2] = msgs

      assert_prev_count alice, 2

      assert(ping_bob_1.message instanceof Proteus.message.CipherMessage)
      assert(ping_bob_2.message instanceof Proteus.message.CipherMessage)

      assert_decrypt 'Ping1!', bob.decrypt bob_store, ping_bob_1

    .then ->
      assert(bob.session_states[bob.session_tag].state.recv_chains.length is 2)
      assert_decrypt 'Ping2!', bob.decrypt bob_store, ping_bob_2

    .then ->
      assert(bob.session_states[bob.session_tag].state.recv_chains.length is 2)
      bob.encrypt 'Pong!'

    .then (m) ->
      pong_alice = m
      assert_prev_count bob, 1
      assert_decrypt 'Pong!', alice.decrypt alice_store, pong_alice

    .then ->
      assert(alice.session_states[alice.session_tag].state.recv_chains.length is 3)
      assert_prev_count alice, 2
      assert_decrypt 'Hello delay!', bob.decrypt bob_store, hello_bob_delayed

    .then ->
      assert(bob.session_states[bob.session_tag].state.recv_chains.length is 2)
      assert_prev_count bob, 1

      assert_serialise_deserialise alice_ident, alice
      assert_serialise_deserialise bob_ident, bob

    .then((() -> done()), (err) -> done(err))

  it 'should limit the number of receive chains', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = null
    bob = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      alice.encrypt 'Hello Bob!'

    .then (hello_bob) ->
      assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    .then (s) ->
      bob = s

      assert(alice.session_states[alice.session_tag].state.recv_chains.length is 1)
      assert(bob.session_states[bob.session_tag].state.recv_chains.length is 1)

      Promise.all([0..(Proteus.session.Session.MAX_RECV_CHAINS * 2)].map(() ->
        return new Promise (resolve, reject) ->
          bob.encrypt 'ping'
          .then (m) ->
            assert_decrypt 'ping', alice.decrypt alice_store, m

          .then ->
            alice.encrypt 'pong'

          .then (m) ->
            assert_decrypt 'pong', bob.decrypt bob_store, m

          .then ->
            assert.isAtMost(alice.session_states[alice.session_tag].state.recv_chains.length,
              Proteus.session.Session.MAX_RECV_CHAINS)
            assert.isAtMost(bob.session_states[bob.session_tag].state.recv_chains.length,
              Proteus.session.Session.MAX_RECV_CHAINS)

            resolve()))

    .then((() -> done()), (err) -> done(err))

  it 'should handle a counter mismatch', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = null
    bob = null

    ciphertexts = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      alice.encrypt 'Hello Bob!'

    .then (m) ->
      assert_init_from_message bob_ident, bob_store, m, 'Hello Bob!'

    .then (s) ->
      bob = s

      Promise.all(['Hello1', 'Hello2', 'Hello3', 'Hello4', 'Hello5'].map (x) -> bob.encrypt(x))

    .then (t) ->
      ciphertexts = t
      assert_decrypt 'Hello2', alice.decrypt alice_store, ciphertexts[1]

    .then ->
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 1)
      assert_serialise_deserialise alice_ident, alice
      assert_decrypt 'Hello1', alice.decrypt alice_store, ciphertexts[0]

    .then ->
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 0)
      assert_decrypt 'Hello3', alice.decrypt alice_store, ciphertexts[2]

    .then ->
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 0)
      assert_decrypt 'Hello5', alice.decrypt alice_store, ciphertexts[4]
    .then ->
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 1)
      assert_decrypt 'Hello4', alice.decrypt alice_store, ciphertexts[3]

    .then ->
      assert(alice.session_states[alice.session_tag].state.recv_chains[0].message_keys.length is 0)

      Promise.all(ciphertexts.map (x) ->
        return new Promise (resolve, reject) ->
          alice.decrypt alice_store, x
          .then ->
            assert.fail 'should have raised Proteus.errors.DecryptError.DuplicateMessage'

          .catch (e) ->
            assert.instanceOf e, Proteus.errors.DecryptError.DuplicateMessage
            resolve())

    .then ->
      assert_serialise_deserialise alice_ident, alice
      assert_serialise_deserialise bob_ident, bob

    .then((() -> done()), (err) -> done(err))

  it 'should handle multiple prekey messages', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    bob_store = new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = null
    bob = null

    hello_bob1 = null
    hello_bob2 = null
    hello_bob3 = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      Promise.all(['Hello Bob1!', 'Hello Bob2!', 'Hello Bob3!'].map (x) -> alice.encrypt x)

    .then (m) ->
      [hello_bob1, hello_bob2, hello_bob3] = m
      assert_init_from_message bob_ident, bob_store, hello_bob1, 'Hello Bob1!'

    .then (s) ->
      bob = s
      assert(Object.keys(bob.session_states).length is 1)
      assert_decrypt 'Hello Bob2!', bob.decrypt bob_store, hello_bob2

    .then ->
      assert(Object.keys(bob.session_states).length is 1)
      assert_decrypt 'Hello Bob3!', bob.decrypt bob_store, hello_bob3

    .then ->
      assert(Object.keys(bob.session_states).length is 1)

      assert_serialise_deserialise alice_ident, alice
      assert_serialise_deserialise bob_ident, bob

    .then((() -> done()), (err) -> done(err))

  it 'should handle simultaneous prekey messages', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice_prekey = alice_store.prekeys[0]
    alice_bundle = Proteus.keys.PreKeyBundle.new alice_ident.public_key, alice_prekey

    alice = null
    bob = null

    hello_bob = null
    hello_alice = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      alice.encrypt 'Hello Bob!'

    .then (m) ->
      hello_bob = m
      bob = Proteus.session.Session.init_from_prekey bob_ident, alice_bundle

    .then (s) ->
      bob = s
      bob.encrypt 'Hello Alice!'

    .then (m) ->
      hello_alice = m

      assert.notStrictEqual(alice.session_tag.toString(), bob.session_tag.toString())
      assert_decrypt 'Hello Bob!', bob.decrypt bob_store, hello_bob

    .then ->
      assert(Object.keys(bob.session_states).length is 2)
      assert_decrypt 'Hello Alice!', alice.decrypt alice_store, hello_alice

    .then ->
      assert(Object.keys(alice.session_states).length is 2)
      alice.encrypt 'That was fast!'
    .then (m) ->
      assert_decrypt 'That was fast!', bob.decrypt bob_store, m

      bob.encrypt ':-)'
    .then (m) ->
      assert_decrypt ':-)', alice.decrypt alice_store, m

      assert.strictEqual(alice.session_tag.toString(), bob.session_tag.toString())

      assert_serialise_deserialise alice_ident, alice
      assert_serialise_deserialise bob_ident, bob

    .then((() -> done()), (err) -> done(err))

  it 'should handle simultaneous repeated messages', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice_prekey = alice_store.prekeys[0]
    alice_bundle = Proteus.keys.PreKeyBundle.new alice_ident.public_key, alice_prekey

    alice = null
    bob = null

    hello_bob = null
    echo_bob1 = null
    echo_bob2 = null
    stop_bob = null
    hello_alice = null
    echo_alice1 = null
    echo_alice2 = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      alice.encrypt 'Hello Bob!'
    .then (m) ->
      hello_bob = m
      Proteus.session.Session.init_from_prekey bob_ident, alice_bundle

    .then (s) ->
      bob = s
      bob.encrypt 'Hello Alice!'

    .then (m) ->
      hello_alice = m

      assert(alice.session_tag.toString() isnt bob.session_tag.toString())

      assert_decrypt 'Hello Bob!', bob.decrypt bob_store, hello_bob

    .then ->
      assert_decrypt 'Hello Alice!', alice.decrypt alice_store, hello_alice

    .then ->
      alice.encrypt 'Echo Bob1!'

    .then (m) ->
      echo_bob1 = m
      bob.encrypt 'Echo Alice1!'

    .then (m) ->
      echo_alice1 = m

      assert_decrypt 'Echo Bob1!', bob.decrypt bob_store, echo_bob1
      assert(Object.keys(bob.session_states).length is 2)
      assert_decrypt 'Echo Alice1!', alice.decrypt alice_store, echo_alice1
      assert(Object.keys(alice.session_states).length is 2)
      assert(alice.session_tag.toString() isnt bob.session_tag.toString())

      alice.encrypt 'Echo Bob2!'

    .then (m) ->
      echo_bob2 = m
      bob.encrypt 'Echo Alice2!'

    .then (m) ->
      echo_alice2 = m

      assert_decrypt 'Echo Bob2!', bob.decrypt bob_store, echo_bob2
    .then ->
      assert(Object.keys(bob.session_states).length is 2)
      assert_decrypt 'Echo Alice2!', alice.decrypt alice_store, echo_alice2

    .then ->
      assert(Object.keys(alice.session_states).length is 2)
      assert(alice.session_tag.toString() isnt bob.session_tag.toString())
      alice.encrypt 'Stop it!'

    .then (m) ->
      stop_bob = m
      assert_decrypt 'Stop it!', bob.decrypt bob_store, stop_bob
      bob.encrypt 'OK'

    .then (m) ->
      answer_alice = m
      assert_decrypt 'OK', alice.decrypt alice_store, answer_alice

      assert(alice.session_tag.toString() is bob.session_tag.toString())

      assert_serialise_deserialise alice_ident, alice
      assert_serialise_deserialise bob_ident, bob

    .then((() -> done()), (err) -> done(err))

  it 'should handle mass communication', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = null
    bob = null
    hello_bob = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      alice.encrypt 'Hello Bob!'

    .then (m) ->
      hello_bob = m

      assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'
    .then (s) ->
      bob = s

      # XXX: need to serialize/deserialize to/from CBOR here
      Promise.all([0...999].map(-> bob.encrypt 'Hello Alice!'))
    .then (messages) ->
      Promise.all(messages.map((m) -> assert_decrypt 'Hello Alice!', alice.decrypt alice_store,
        Proteus.message.Envelope.deserialise(m.serialise())))

    .then ->
      assert_serialise_deserialise alice_ident, alice
      assert_serialise_deserialise bob_ident, bob

    .then((() -> done()), (err) -> done(err))

  it 'should fail retry init from message', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    bob_store = new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = null
    bob = null
    hello_bob = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      alice.encrypt 'Hello Bob!'

    .then (m) ->
      hello_bob = m
      assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    .then (s) ->
      bob = s
      Proteus.session.Session.init_from_message bob_ident, bob_store, hello_bob

    .then ->
      assert.fail 'should have thrown Proteus.errors.ProteusError'

    .catch (e) ->
      assert.instanceOf e, Proteus.errors.ProteusError

    .then((() -> done()), (err) -> done(err))

  it 'pathological case', (done) ->
    @timeout 0

    num_alices = 32

    alices = null
    bob = null

    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    bob_store = new TestStore Proteus.keys.PreKey.generate_prekeys 0, num_alices

    Promise.all(bob_store.prekeys.map((pk) ->
      bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, pk
      return Proteus.session.Session.init_from_prekey alice_ident, bundle))
    .then (s) ->
      alices = s
      assert(alices.length is num_alices)
      alices[0].encrypt 'Hello Bob!'

    .then (m) ->
      assert_init_from_message bob_ident, bob_store, m, 'Hello Bob!'

    .then (s) ->
      bob = s

      Promise.all(alices.map (a) ->
        return new Promise (resolve, reject) ->
          Promise.all([0..900].map(-> a.encrypt 'hello'))
          .then ->
            a.encrypt 'Hello Bob!'

          .then (m) ->
            resolve assert_decrypt 'Hello Bob!', bob.decrypt bob_store, m)

    .then ->
      assert(Object.keys(bob.session_states).length is num_alices)

      Promise.all(alices.map (a) ->
        a.encrypt 'Hello Bob!'
        .then (m) ->
          assert_decrypt 'Hello Bob!', bob.decrypt bob_store, m)

    .then((() -> done()), (err) -> done(err))

  it 'skipped message keys', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [alice_store, bob_store] = [0..1].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 10)

    bob_prekey = bob_store.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = null
    bob = null
    hello_bob = null
    hello_alice0 = null
    hello_alice2 = null
    hello_bob0 = null
    hello_again0 = null
    hello_again1 = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      alice.encrypt 'Hello Bob!'

    .then (m) ->
      hello_bob = m

      do ->
        s = alice.session_states[alice.session_tag].state
        assert(s.recv_chains.length is 1)
        assert(s.recv_chains[0].chain_key.idx is 0)
        assert(s.send_chain.chain_key.idx is 1)
        assert(s.recv_chains[0].message_keys.length is 0)

      assert_init_from_message bob_ident, bob_store, hello_bob, 'Hello Bob!'

    .then (s) ->
      bob = s

      do ->
        # Normal exchange. Bob has created a new receive chain without skipped message keys.

        s = bob.session_states[bob.session_tag].state
        assert(s.recv_chains.length is 1)
        assert(s.recv_chains[0].chain_key.idx is 1)
        assert(s.send_chain.chain_key.idx is 0)
        assert(s.recv_chains[0].message_keys.length is 0)

      bob.encrypt 'Hello0'
    .then (m) ->
      hello_alice0 = m
      bob.encrypt 'Hello1' # unused result
      bob.encrypt 'Hello2'

    .then (m) ->
      hello_alice2 = m
      alice.decrypt alice_store, hello_alice2

    .then ->
      do ->
        # Alice has two skipped message keys in her new receive chain.

        s = alice.session_states[alice.session_tag].state
        assert(s.recv_chains.length is 2)
        assert(s.recv_chains[0].chain_key.idx is 3)
        assert(s.send_chain.chain_key.idx is 0)
        assert(s.recv_chains[0].message_keys.length is 2)
        assert(s.recv_chains[0].message_keys[0].counter is 0)
        assert(s.recv_chains[0].message_keys[1].counter is 1)

      alice.encrypt 'Hello0'

    .then (m) ->
      hello_bob0 = m
      assert_decrypt 'Hello0', bob.decrypt bob_store, hello_bob0

    .then ->

      do ->
        # For Bob everything is normal still. A new message from Alice means a
        # new receive chain has been created and again no skipped message keys.

        s = bob.session_states[bob.session_tag].state
        assert(s.recv_chains.length is 2)
        assert(s.recv_chains[0].chain_key.idx is 1)
        assert(s.send_chain.chain_key.idx is 0)
        assert(s.recv_chains[0].message_keys.length is 0)

      assert_decrypt 'Hello0', alice.decrypt alice_store, hello_alice0

    .then ->
      do ->
        # Alice received the first of the two missing messages. Therefore
        # only one message key is still skipped (counter value = 1).

        s = alice.session_states[alice.session_tag].state
        assert(s.recv_chains.length is 2)
        assert(s.recv_chains[0].message_keys.length is 1)
        assert(s.recv_chains[0].message_keys[0].counter is 1)

      bob.encrypt 'Again0'
    .then (m) ->
      hello_again0 = m
      bob.encrypt 'Again1'

    .then (m) ->
      hello_again1 = m
      assert_decrypt 'Again1', alice.decrypt alice_store, hello_again1

    .then ->
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

    .then((() -> done()), (err) -> done(err))

  it 'replaced prekeys', (done) ->
    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())
    [bob_store1, bob_store2] = [0..2].map(-> new TestStore Proteus.keys.PreKey.generate_prekeys 0, 1)

    bob_prekey = bob_store1.prekeys[0]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = null
    bob = null
    hello_bob1 = null
    hello_bob2 = null
    hello_bob3 = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      alice.encrypt 'Hello Bob1!'

    .then (m) ->
      hello_bob1 = m
      assert_init_from_message bob_ident, bob_store1, hello_bob1, 'Hello Bob1!'

    .then (s) ->
      bob = s
      assert(Object.keys(bob.session_states).length is 1)

      alice.encrypt 'Hello Bob2!'

    .then (m) ->
      hello_bob2 = m
      assert_decrypt 'Hello Bob2!', bob.decrypt bob_store1, hello_bob2
      assert(Object.keys(bob.session_states).length is 1)

      alice.encrypt 'Hello Bob3!'

    .then (m) ->
      hello_bob3 = m
      assert_decrypt 'Hello Bob3!', bob.decrypt bob_store2, hello_bob3
      assert(Object.keys(bob.session_states).length is 1)

    .then((() -> done()), (err) -> done(err))

  it 'max counter gap', (done) ->
    @timeout 0

    [alice_ident, bob_ident] = [0..1].map(-> Proteus.keys.IdentityKeyPair.new())

    keys = []
    keys[Proteus.keys.PreKey.MAX_PREKEY_ID] = Proteus.keys.PreKey.last_resort()
    bob_store = new TestStore keys

    bob_prekey = bob_store.prekeys[Proteus.keys.PreKey.MAX_PREKEY_ID]
    bob_bundle = Proteus.keys.PreKeyBundle.new bob_ident.public_key, bob_prekey

    alice = null
    bob = null

    Proteus.session.Session.init_from_prekey alice_ident, bob_bundle
    .then (s) ->
      alice = s
      alice.encrypt 'Hello Bob1!'
    .then (hello_bob1) ->
      assert_init_from_message bob_ident, bob_store, hello_bob1, 'Hello Bob1!'

    .then (s) ->
      bob = s
      assert(Object.keys(bob.session_states).length is 1)

      Promise.all(Array.apply(null, Array(1001)).map((_, i) ->
        return new Promise (resolve, reject) ->
          alice.encrypt 'Hello Bob2!'
          .then (hello_bob2) ->
            assert_decrypt 'Hello Bob2!', bob.decrypt bob_store, hello_bob2
            assert.strictEqual(Object.keys(bob.session_states).length, 1)
            resolve()))

    .then((() -> done()), (err) -> done(err))
