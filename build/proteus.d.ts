export module CBOR {
  class Encoder {
    encode(value: any): any;
  }

  class Decoder {
    decode(value: any): any;
  }
}

export module Proteus {
  module derived {
    class CipherKey {
      constructor();

      key: Uint8Array;

      static decode(d: CBOR.Decoder): Proteus.derived.CipherKey;
      decrypt(ciphertext: Uint8Array, nonce: Uint8Array): Uint8Array;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      encrypt(plaintext: ArrayBuffer|string|Uint8Array, nonce: Uint8Array): Uint8Array;
      static new(key: Uint8Array): Proteus.derived.MacKey;
    }

    class DerivedSecrets {
      constructor();

      cipher_key: Proteus.derived.CipherKey;
      mac_key: Proteus.derived.MacKey;

      static kdf(input: Array<number>, salt: Uint8Array, info: string): Proteus.derived.DerivedSecrets;
      static kdf_without_salt(input: Array<number>, info: string): Proteus.derived.DerivedSecrets;
    }

    class MacKey {
      constructor();

      key: Uint8Array;

      static decode(d: CBOR.Decoder): Proteus.derived.MacKey;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static new(key: Uint8Array): Proteus.derived.MacKey;
      sign(msg: string|Uint8Array): Uint8Array;
      verify(signature: Uint8Array, msg: Uint8Array): boolean;
    }
  }

  module keys {
    class IdentityKey {
      constructor();

      public_key: Proteus.keys.PublicKey;

      static decode(d: CBOR.Decoder): Proteus.keys.IdentityKey;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      fingerprint(): string;
      static new(public_key: Proteus.keys.PublicKey): Proteus.keys.IdentityKey;
      tostring(): string;
    }

    class IdentityKeyPair {
      constructor();

      public_key: Proteus.keys.PublicKey;
      secret_key: Proteus.keys.SecretKey;
      version: number;

      static decode(d: CBOR.Decoder): Proteus.keys.IdentityKeyPair;
      static deserialise(buf: ArrayBuffer): Proteus.keys.IdentityKeyPair;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static new(): Proteus.keys.IdentityKeyPair;
      serialise(): ArrayBuffer;
    }

    class KeyPair {
      constructor();

      secret_key: Proteus.keys.SecretKey;
      public_key: Proteus.keys.PublicKey;

      private _construct_private_key(ed25519_key_pair: Object): Proteus.keys.SecretKey;
      private _construct_public_key(ed25519_key_pair: Object): Proteus.keys.PublicKey;
      static decode(d: CBOR.Decoder): Proteus.keys.KeyPair;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static new(): Proteus.keys.KeyPair;
    }

    class PreKey {
      constructor();

      key_id: number;
      key_pair: Proteus.keys.KeyPair;
      version: number;

      static decode(d: CBOR.Decoder): Proteus.keys.PreKey;
      static deserialise(buf: ArrayBuffer): Proteus.keys.PreKey;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static generate_prekeys(start: number, size: number): Array<Proteus.keys.KeyPair>;
      static last_resort(): Proteus.keys.PreKey;
      static new(pre_key_id: number): Proteus.keys.PreKey;
      serialise(): ArrayBuffer;
    }

    type PreKeyAuth = 'Invalid' | 'Unknown' | 'Valid';

    class PreKeyBundle {
      constructor();

      identity_key:  Proteus.keys.IdentityKey;
      prekey_id: number;
      public_key: Proteus.keys.PublicKey;
      signature: Uint8Array;
      version: number;

      static decode(d: CBOR.Decoder): Proteus.keys.PreKeyBundle;
      static deserialise(buf: ArrayBuffer): Proteus.keys.PreKeyBundle;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static new(identity_key: Proteus.keys.IdentityKey, prekey: Proteus.keys.PreKey): Proteus.keys.PreKeyBundle;
      serialise(): ArrayBuffer;
      static signed(identity_key: Proteus.keys.IdentityKey, prekey: Proteus.keys.PreKey): Proteus.keys.PreKeyBundle;
      verify(): Proteus.keys.PreKeyAuth;
    }

    class PublicKey {
      constructor();

      pub_curve: Uint8Array;
      pub_edward: Uint8Array;

      static decode(d: CBOR.Decoder): Proteus.keys.PublicKey;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      fingerprint(): string;
      static new(pub_edward: Uint8Array, pub_curve: Uint8Array): Proteus.keys.PublicKey;
      verify(signature: Uint8Array, message: string): boolean;
    }

    class SecretKey {
      constructor();

      sec_curve: Uint8Array;
      sec_edward: Uint8Array;

      static decode(d: CBOR.Decoder): Proteus.keys.SecretKey;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      shared_secret(public_key: Proteus.keys.PublicKey): Uint8Array;
      sign(message: string): Uint8Array;
      static new(pub_edward: Uint8Array, pub_curve: Uint8Array): Proteus.keys.SecretKey;
    }
  }

  module message {
    class CipherMessage {
      constructor();

      cipher_text: Uint8Array;
      counter: number;
      prev_counter: number;
      ratchet_key: Proteus.keys.PublicKey;
      session_tag: Proteus.message.SessionTag;

      static decode(d: CBOR.Decoder): Proteus.message.CipherMessage;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static new(session_tag: Proteus.message.SessionTag, counter: number, prev_counter: number, ratchet_key: Proteus.keys.PublicKey, cipher_text: Uint8Array): Proteus.message.SessionTag;
    }

    class Envelope {
      constructor();

      _message_enc: Uint8Array;
      mac: Uint8Array;
      message: Proteus.message.Message;
      version: number;

      static new(mac_key: Proteus.derived.MacKey, message: Proteus.message.Message): Proteus.message.Envelope;
    }

    class Message {
      constructor();

      static deserialise(buf: ArrayBuffer): Proteus.message.Message;
      serialise(): ArrayBuffer;
    }

    class PreKeyMessage {
      constructor();

      base_key: Proteus.keys.PublicKey;
      identity_key: Proteus.keys.IdentityKey;
      message: Proteus.message.CipherMessage;
      prekey_id: number;

      static decode(d: CBOR.Decoder): Proteus.message.PreKeyMessage;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static new(prekey_id: number, base_key: Proteus.keys.PublicKey, identity_key: Proteus.keys.IdentityKey, message: Proteus.message.CipherMessage): Proteus.message.PreKeyMessage;
    }

    class SessionTag {
      constructor();

      tag: Uint8Array;

      encode(e: CBOR.Encoder): CBOR.Encoder;
      static decode(d: CBOR.Decoder): Proteus.message.SessionTag;
      static new(): Proteus.message.SessionTag;
      tostring(): string;
    }
  }

  module session {
    class ChainKey {
      constructor();

      idx: number;
      key: Proteus.derived.MacKey;

      static decode(d: CBOR.Decoder): Proteus.session.ChainKey;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static from_mac_key(key: Proteus.derived.MacKey, counter: number): Proteus.session.ChainKey;
      message_keys(): Proteus.session.MessageKeys;
      next(): Proteus.session.ChainKey;
    }

    class MessageKeys {
      constructor();

      cipher_key: Proteus.derived.CipherKey;
      counter: number;
      mac_key: Proteus.derived.MacKey;

      private _counter_as_nonce(): Uint8Array;
      static decode(d: CBOR.Decoder): Proteus.session.MessageKeys;
      decrypt(ciphertext: Uint8Array): Uint8Array;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      encrypt(plaintext: string|Uint8Array): Uint8Array;
      static new(key: Uint8Array): Proteus.derived.MacKey;
    }

    class PreKeyStore {
      get_prekey(prekey_id: number): Promise<Proteus.keys.PreKey>;
      remove(prekey_id: number): Promise<void>;
    }

    class RecvChain {
      constructor();

      chain_key: Proteus.session.ChainKey;
      ratchet_key: Proteus.keys.PublicKey;
      message_keys: Array<Proteus.session.MessageKeys>;

      commit_message_keys(keys: Array<Proteus.session.MessageKeys>): void;
      static decode(d: CBOR.Decoder): Proteus.session.RecvChain;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static new(chain_key: Proteus.session.ChainKey, public_key: Proteus.keys.PublicKey): Proteus.message.PreKeyMessage;
      stage_message_keys(msg: Proteus.message.CipherMessage): Array<Proteus.session.ChainKey|Proteus.session.MessageKeys>;
      try_message_keys(envelope: Proteus.message.Envelope, msg: Proteus.message.CipherMessage): Uint8Array;
    }

    class RootKey {
      constructor();

      key: Proteus.derived.CipherKey;

      static decode(d: CBOR.Decoder): Proteus.session.RootKey;
      dh_ratchet(ours: Proteus.keys.KeyPair, theirs: Proteus.keys.PublicKey): Array<Proteus.session.RootKey|Proteus.session.ChainKey>;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static from_cipher_key(cipher_key: Proteus.derived.CipherKey): Proteus.session.RootKey;
    }

    class SendChain {
      constructor();

      chain_key: Proteus.session.ChainKey;
      ratchet_key: Proteus.keys.KeyPair;

      static decode(d: CBOR.Decoder): Proteus.session.SendChain;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      static new(chain_key: Proteus.session.ChainKey, keypair: Proteus.keys.KeyPair): Proteus.session.SendChain;
    }

    class Session {
      constructor();

      counter: number;
      local_identity: any;
      pending_prekey: any;
      remote_identity: any;
      session_states: any;
      session_tag: Proteus.message.SessionTag;
      version: number;

      private _decrypt_cipher_message(envelope: Proteus.message.Envelope, msg: Proteus.message.CipherMessage): Uint8Array;
      private _evict_oldest_session_state(): void;
      private _insert_session_state(tag: Proteus.message.SessionTag, state: Proteus.session.SessionState): number|void;
      private _new_state(prekey_store: Proteus.session.PreKeyStore, prekey_message: Proteus.message.PreKeyMessage): Promise<Proteus.session.SessionState>;
      static decode(local_identity: Proteus.keys.IdentityKeyPair, d: CBOR.Decoder): Proteus.session.Session;
      decrypt(prekey_store: Proteus.session.PreKeyStore, envelope: Proteus.message.Envelope): Uint8Array;
      static deserialise(local_identity: Proteus.keys.IdentityKeyPair, buf: ArrayBuffer): Proteus.session.Session;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      encrypt(plaintext: string|Uint8Array): Promise<Proteus.message.Envelope>;
      get_local_identity(): Proteus.keys.PublicKey;
      static init_from_message(our_identity: Proteus.keys.IdentityKeyPair, prekey_store: Proteus.session.PreKeyStore, envelope: Proteus.message.Envelope): Promise<Array<Proteus.session.Session|Uint8Array>>;
      static init_from_prekey(local_identity: Proteus.keys.IdentityKeyPair, remote_pkbundle: Proteus.keys.PreKeyBundle): Promise<Proteus.session.Session>;
      serialise(): ArrayBuffer;
    }

    class SessionState {
      constructor();

      prev_counter: number;
      recv_chains: Array<Proteus.session.RecvChain>;
      root_key: Proteus.session.RootKey;
      send_chain: Proteus.session.SendChain;

      static decode(d: CBOR.Decoder): Proteus.session.SessionState;
      decrypt(envelope: Proteus.message.Envelope, msg: Proteus.message.CipherMessage): Uint8Array;
      static deserialise(buf: ArrayBuffer): Proteus.session.SessionState;
      encode(e: CBOR.Encoder): CBOR.Encoder;
      encrypt(identity_key: Proteus.keys.IdentityKey, pending: Array<number>, tag: Proteus.message.SessionTag, plaintext: string|Uint8Array): Proteus.message.Envelope;
      static init_as_alice(alice_identity_pair: Proteus.keys.IdentityKeyPair, alice_base: Proteus.keys.KeyPair, bob_pkbundle: Proteus.keys.PreKeyBundle): Proteus.session.SessionState;
      static init_as_bob(bob_ident: Proteus.keys.IdentityKeyPair, bob_prekey: Proteus.keys.KeyPair, alice_ident: Proteus.keys.IdentityKey, alice_base: Proteus.keys.PublicKey): Proteus.session.SessionState;
      ratchet(ratchet_key: Proteus.keys.KeyPair): void;
      serialise(): ArrayBuffer;
    }
  }
}
