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

CBOR = require 'wire-webapp-cbor'

DontCallConstructor = require '../errors/DontCallConstructor'
ClassUtil = require '../util/ClassUtil'
TypeUtil = require '../util/TypeUtil'

ProteusError = require '../errors/ProteusError'
DecryptError = require '../errors/DecryptError'
DecodeError = require '../errors/DecodeError'

IdentityKeyPair = require '../keys/IdentityKeyPair'
IdentityKey = require '../keys/IdentityKey'
PreKeyBundle = require '../keys/PreKeyBundle'
PublicKey = require '../keys/PublicKey'
KeyPair = require '../keys/KeyPair'
PreKey = require '../keys/PreKey'

Envelope = require '../message/Envelope'
CipherMessage = require '../message/CipherMessage'
PreKeyMessage = require '../message/PreKeyMessage'
SessionTag = require '../message/SessionTag'

PreKeyStore = require './PreKeyStore'

module.exports = class Session
  @MAX_RECV_CHAINS:     5
  @MAX_SESSION_STATES:  100

  constructor: ->
    @counter = 0
    @local_identity = null
    @pending_prekey = null
    @remote_identity = null
    @session_states = null
    @session_tag = null
    @version = 1

    throw new DontCallConstructor @

  ###
  @param local_identity [IdentityKeyPair] Alice's Identity Key Pair
  @param remote_pkbundle [Proteus.keys.PreKeyBundle] Bob's Pre-Key Bundle
  ###
  @init_from_prekey: (local_identity, remote_pkbundle) ->
    return new Promise (resolve) =>
      TypeUtil.assert_is_instance IdentityKeyPair, local_identity
      TypeUtil.assert_is_instance PreKeyBundle, remote_pkbundle

      alice_base = KeyPair.new()

      state = SessionState.init_as_alice local_identity, alice_base, remote_pkbundle

      session_tag = SessionTag.new()

      session = ClassUtil.new_instance Session
      session.session_tag = session_tag
      session.local_identity = local_identity
      session.remote_identity = remote_pkbundle.identity_key
      session.pending_prekey = [remote_pkbundle.prekey_id, alice_base.public_key]
      session.session_states = {}

      session._insert_session_state session_tag, state
      resolve session

  @init_from_message: (our_identity, prekey_store, envelope) ->
    return new Promise (resolve, reject) =>
      TypeUtil.assert_is_instance IdentityKeyPair, our_identity
      TypeUtil.assert_is_instance PreKeyStore, prekey_store
      TypeUtil.assert_is_instance Envelope, envelope

      pkmsg = switch
        when envelope.message instanceof CipherMessage
          throw new DecryptError.InvalidMessage 'Can\'t initialise a session from a CipherMessage.'
        when envelope.message instanceof PreKeyMessage
          envelope.message
        else
          throw new DecryptError.InvalidMessage

      session = ClassUtil.new_instance Session
      session.session_tag = pkmsg.message.session_tag
      session.local_identity = our_identity
      session.remote_identity = pkmsg.identity_key
      session.pending_prekey = null
      session.session_states = {}

      session._new_state(prekey_store, pkmsg)
      .then (state) =>
        plain = state.decrypt(envelope, pkmsg.message)
        session._insert_session_state(pkmsg.message.session_tag, state)

        if pkmsg.prekey_id < PreKey.MAX_PREKEY_ID
          prekey_store.remove(pkmsg.prekey_id)
          .then ->
            resolve [session, plain]
          .catch (error) ->
            reject new DecryptError.PrekeyNotFound "Could not delete PreKey: #{error.message}"
        else
          resolve [session, plain]
      .catch reject

  _new_state: (pre_key_store, pre_key_message) ->
    return pre_key_store.get_prekey pre_key_message.prekey_id
    .then (pre_key) =>
      if pre_key
        return SessionState.init_as_bob @local_identity, pre_key.key_pair, pre_key_message.identity_key, pre_key_message.base_key
      throw new ProteusError 'Unable to get PreKey'

  _insert_session_state: (tag, state) ->
    if tag in @session_states
      @session_states[tag].state = state
    else
      if @counter >= Number.MAX_SAFE_INTEGER
        @session_states = {}
        @counter = 0

      @session_states[tag] = {idx: @counter, tag: tag, state: state}
      @counter++

    if @session_tag.toString() isnt tag.toString()
      @session_tag = tag

    obj_size = (obj) ->
      return Object.keys(obj).length

    if obj_size(@session_states) < Session.MAX_SESSION_STATES
      return

    # if we get here, it means that we have more than MAX_SESSION_STATES and
    # we need to evict the oldest one.

    @_evict_oldest_session_state()

  _evict_oldest_session_state: ->
    oldest = Object.keys @session_states
    .filter (obj) => obj.toString() isnt @session_tag
    .reduce (lowest, obj, index) =>
      if @session_states[obj].idx < @session_states[lowest].idx then obj.toString() else lowest

    delete @session_states[oldest]

  get_local_identity: ->
    return @local_identity.public_key

  ###
  @param plaintext [String, Uint8Array] The plaintext which needs to be encrypted
  @return [Proteus.message.Envelope] Encrypted message
  ###
  encrypt: (plaintext) ->
    return new Promise (resolve, reject) =>
      state = @session_states[@session_tag]

      if not state
        return reject new ProteusError "Could not find session for tag '#{@session_tag?.toString()}'."

      resolve state.state.encrypt @local_identity.public_key, @pending_prekey, @session_tag, plaintext

  decrypt: (prekey_store, envelope) ->
    return new Promise (resolve) =>
      TypeUtil.assert_is_instance PreKeyStore, prekey_store
      TypeUtil.assert_is_instance Envelope, envelope

      msg = envelope.message
      switch
        when msg instanceof CipherMessage
          return resolve @_decrypt_cipher_message envelope, envelope.message
        when msg instanceof PreKeyMessage
          throw new DecryptError.RemoteIdentityChanged if msg.identity_key.fingerprint() isnt @remote_identity.fingerprint()
          return resolve @_decrypt_prekey_message envelope, msg, prekey_store
        else
          throw new DecryptError 'Unknown message type.'

  _decrypt_prekey_message: (envelope, msg, prekey_store) =>
    return Promise.resolve()
    .then =>
      return @_decrypt_cipher_message envelope, msg.message
    .catch (error) =>
      if error instanceof DecryptError.InvalidSignature or error instanceof DecryptError.InvalidMessage
        return @_new_state(prekey_store, msg)
        .then (state) =>
          plaintext = state.decrypt envelope, msg.message

          if msg.prekey_id != PreKey.MAX_PREKEY_ID
            prekey_store.remove msg.prekey_id

          @_insert_session_state msg.message.session_tag, state
          @pending_prekey = null

          return plaintext
      throw error

  _decrypt_cipher_message: (envelope, msg) ->
    state = @session_states[msg.session_tag]
    if not state
      throw new DecryptError.InvalidMessage "We received a message with session tag '#{msg.session_tag?.toString()}', but we don't have a session for this tag."

    # serialise and de-serialise for a deep clone
    # THIS IS IMPORTANT, DO NOT MUTATE THE SESSION STATE IN-PLACE
    # mutating in-place can lead to undefined behavior and undefined state in edge cases
    state = SessionState.deserialise state.state.serialise()

    plaintext = state.decrypt envelope, msg

    @pending_prekey = null

    @_insert_session_state msg.session_tag, state
    return plaintext

  serialise: ->
    e = new CBOR.Encoder()
    @encode e
    return e.get_buffer()

  @deserialise: (local_identity, buf) ->
    TypeUtil.assert_is_instance IdentityKeyPair, local_identity
    TypeUtil.assert_is_instance ArrayBuffer, buf

    d = new CBOR.Decoder buf
    return Session.decode local_identity, d

  encode: (e) ->
    e.object 6
    e.u8 0; e.u8 @version
    e.u8 1; @session_tag.encode e
    e.u8 2; @local_identity.public_key.encode e
    e.u8 3; @remote_identity.encode e

    e.u8 4
    if @pending_prekey
      e.object 2
      e.u8 0; e.u16 @pending_prekey[0]
      e.u8 1; @pending_prekey[1].encode e
    else
      e.null()

    e.u8 5
    e.object Object.keys(@session_states).length
    for _, state of @session_states
      state.tag.encode e
      state.state.encode e

  @decode: (local_identity, d) ->
    TypeUtil.assert_is_instance IdentityKeyPair, local_identity
    TypeUtil.assert_is_instance CBOR.Decoder, d

    self = ClassUtil.new_instance Session

    nprops = d.object()
    for [0..(nprops - 1)]
      switch d.u8()
        when 0 then self.version = d.u8()
        when 1 then self.session_tag = SessionTag.decode d
        when 2
          ik = IdentityKey.decode d
          if local_identity.public_key.fingerprint() isnt ik.fingerprint()
            throw new DecodeError.LocalIdentityChanged

          self.local_identity = local_identity

        when 3 then self.remote_identity = IdentityKey.decode d
        when 4
          switch d.optional(-> d.object())
            when null then self.pending_prekey = null
            when 2
              self.pending_prekey = [null, null]

              for _ in [0..1]
                switch d.u8()
                  when 0 then self.pending_prekey[0] = d.u16()
                  when 1 then self.pending_prekey[1] = PublicKey.decode d

            else
              throw new DecodeError.InvalidType

        when 5
          self.session_states = {}

          for i in [0..(d.object() - 1)]
            tag = SessionTag.decode d
            self.session_states[tag] = {
              idx: i
              tag: tag
              state: SessionState.decode d
            }

        else d.skip()

    TypeUtil.assert_is_integer self.version
    TypeUtil.assert_is_instance SessionTag, self.session_tag
    TypeUtil.assert_is_instance IdentityKeyPair, self.local_identity
    TypeUtil.assert_is_instance IdentityKey, self.remote_identity
    TypeUtil.assert_is_instance Object, self.session_states

    return self

SessionState = require './SessionState'
