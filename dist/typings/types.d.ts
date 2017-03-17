/** @module derived */
module derived {
   /** @class CipherKey */
   class CipherKey {
       /** @class CipherKey */
       constructor();

       /**
        * @param {Uint8Array} key
        * @returns {derived.MacKey}
        */
       static new(key: Uint8Array): derived.MacKey;

       /**
        * @param {ArrayBuffer|String|Uint8Array} plaintext - The text to encrypt
        * @param {Uint8Array} nonce - Counter as nonce
        * @returns {Uint8Array} Encrypted payload
        */
       encrypt(plaintext: (ArrayBuffer|String|Uint8Array), nonce: Uint8Array): Uint8Array;

       /**
        * @param {Uint8Array} ciphertext
        * @param {Uint8Array} nonce
        * @returns {Uint8Array}
        */
       decrypt(ciphertext: Uint8Array, nonce: Uint8Array): Uint8Array;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Encoder} d
        * @returns {derived.CipherKey}
        */
       static decode(d: CBOR.Encoder): derived.CipherKey;

   }

   /** @class DerivedSecrets */
   class DerivedSecrets {
       /** @class DerivedSecrets */
       constructor();

       /**
        * @param {Array<number>} input
        * @param {Uint8Array} salt
        * @param {string} info
        * @returns {derived.DerivedSecrets}
        */
       static kdf(input: number[], salt: Uint8Array, info: string): derived.DerivedSecrets;

       /**
        * @param {Array<number>} input - Initial key material (usually the Master Key) in byte array format
        * @param {string} info - Key Derivation Data
        * @returns {derived.DerivedSecrets}
        */
       static kdf_without_salt(input: number[], info: string): derived.DerivedSecrets;

   }

   /** @class MacKey */
   class MacKey {
       /** @class MacKey */
       constructor();

       /**
        * @param {Uint8Array} key - Mac Key in byte array format generated by derived secrets
        * @returns {derived.MacKey}
        */
       static new(key: Uint8Array): derived.MacKey;

       /**
        * Hash-based message authentication code
        * @param {string|Uint8Array} msg
        * @returns {Uint8Array}
        */
       sign(msg: (string|Uint8Array)): Uint8Array;

       /**
        * @param {Uint8Array} signature
        * @param {Uint8Array} msg
        * @returns {boolean}
        */
       verify(signature: Uint8Array, msg: Uint8Array): boolean;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {derived.MacKey}
        */
       static decode(d: CBOR.Decoder): derived.MacKey;

   }

}

/** @module errors */
module errors {
   /** @extends ProteusError */
   class DecodeError extends ProteusError {
       /** @extends ProteusError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class InvalidType extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class InvalidArrayLen extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class LocalIdentityChanged extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /** @extends ProteusError */
   class DecryptError extends ProteusError {
       /** @extends ProteusError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class RemoteIdentityChanged extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class InvalidSignature extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class InvalidMessage extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class DuplicateMessage extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class TooDistantFuture extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class OutdatedMessage extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /** @extends DecryptError */
   class PrekeyNotFound extends DecryptError {
       /** @extends DecryptError */
       constructor(message: string);

   }

   /**
    * @class ProteusError
    * @extends Error
    * @returns ProteusError
    */
   class ProteusError extends Error {
       /**
        * @class ProteusError
        * @extends Error
        * @returns ProteusError
        */
       constructor();

   }

}

/** @module keys */
module keys {
   /**
    * Construct a long-term identity key pair.
    * @classdesc Every client has a long-term identity key pair.
    * Long-term identity keys are used to initialise "sessions" with other clients (triple DH).
    */
   class IdentityKey {
       /**
        * Construct a long-term identity key pair.
        * @classdesc Every client has a long-term identity key pair.
        * Long-term identity keys are used to initialise "sessions" with other clients (triple DH).
        */
       constructor();

       /**
        * @param {keys.IdentityKey} public_key
        * @returns {keys.IdentityKey}
        */
       static new(public_key: keys.IdentityKey): keys.IdentityKey;

       /** @returns {string} */
       fingerprint(): string;

       /** @returns {string} */
       toString(): string;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {keys.IdentityKey}
        */
       static decode(d: CBOR.Decoder): keys.IdentityKey;

   }

   /** @class IdentityKeyPair */
   class IdentityKeyPair {
       /** @class IdentityKeyPair */
       constructor();

       /** @returns {keys.IdentityKeyPair} */
       static new(): keys.IdentityKeyPair;

       /** @returns {ArrayBuffer} */
       serialise(): ArrayBuffer;

       /**
        * @param {ArrayBuffer} buf
        * @returns {keys.IdentityKeyPair}
        */
       static deserialise(buf: ArrayBuffer): keys.IdentityKeyPair;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {keys.IdentityKeyPair}
        */
       static decode(d: CBOR.Decoder): keys.IdentityKeyPair;

   }

   /**
    * Construct an ephemeral key pair.
    * @class KeyPair
    */
   class KeyPair {
       /**
        * Construct an ephemeral key pair.
        * @class KeyPair
        */
       constructor();

       /** @returns {keys.KeyPair} */
       static new(): keys.KeyPair;

       /**
        * @description Ed25519 keys can be converted to Curve25519 keys, so that the same key pair can be
        * used both for authenticated encryption (crypto_box) and for signatures (crypto_sign).
        * @param {Uint8Array} ed25519_key_pair - Key pair based on Edwards-curve (Ed25519)
        * @returns {keys.SecretKey} Constructed private key
        * @see https://download.libsodium.org/doc/advanced/ed25519-curve25519.html
        */
       _construct_private_key(ed25519_key_pair: Uint8Array): keys.SecretKey;

       /**
        * @param {libsodium.KeyPair} ed25519_key_pair - Key pair based on Edwards-curve (Ed25519)
        * @returns {keys.PublicKey} Constructed public key
        */
       _construct_public_key(ed25519_key_pair: libsodium.KeyPair): keys.PublicKey;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {keys.KeyPair}
        */
       static decode(d: CBOR.Decoder): keys.KeyPair;

   }

   /**
    * @classdesc Pre-generated (and regularly refreshed) pre-keys.
    * A Pre-Shared Key contains the public long-term identity and ephemeral handshake keys for the initial triple DH.
    */
   class PreKey {
       /**
        * @classdesc Pre-generated (and regularly refreshed) pre-keys.
        * A Pre-Shared Key contains the public long-term identity and ephemeral handshake keys for the initial triple DH.
        */
       constructor();

       /**
        * @returns {number}
        */
       static MAX_PREKEY_ID: any;

       /**
        * @param {number} pre_key_id
        * @returns {keys.PreKey}
        */
       static new(pre_key_id: number): keys.PreKey;

       /** @returns {keys.PreKey} */
       static last_resort(): keys.PreKey;

       /**
        * @param {number} start
        * @param {number} size
        * @returns {Array<keys.PreKey>}
        */
       static generate_prekeys(start: number, size: number): keys.PreKey[];

       /** @returns {ArrayBuffer} */
       serialise(): ArrayBuffer;

       /**
        * @param {ArrayBuffer} buf
        * @returns {keys.PreKey}
        */
       static deserialise(buf: ArrayBuffer): keys.PreKey;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {keys.PreKey}
        */
       static decode(d: CBOR.Decoder): keys.PreKey;

   }

   /** @class PreKeyAuth */
   class PreKeyAuth {
       /** @class PreKeyAuth */
       constructor();

   }

   /** @class PreKeyBundle */
   class PreKeyBundle {
       /** @class PreKeyBundle */
       constructor();

       /**
        * @param {keys.IdentityKey} public_identity_key
        * @param {keys.PreKey} prekey
        * @returns {keys.PreKeyBundle}
        */
       static new(public_identity_key: keys.IdentityKey, prekey: keys.PreKey): keys.PreKeyBundle;

       /**
        * @param {keys.IdentityKeyPair} identity_pair
        * @param {keys.PreKey} prekey
        * @returns {keys.PreKeyBundle}
        */
       static signed(identity_pair: keys.IdentityKeyPair, prekey: keys.PreKey): keys.PreKeyBundle;

       /** @returns {keys.PreKeyAuth} */
       verify(): keys.PreKeyAuth;

       /** @returns {ArrayBuffer} */
       serialise(): ArrayBuffer;

       /** @returns {{id: (number), key: *}} */
       serialised_json(): Object;

       /**
        * @param {ArrayBuffer} buf
        * @returns {keys.PreKeyBundle}
        */
       static deserialise(buf: ArrayBuffer): keys.PreKeyBundle;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {keys.PreKeyBundle}
        */
       static decode(d: CBOR.Decoder): keys.PreKeyBundle;

   }

   /** @class PublicKey */
   class PublicKey {
       /** @class PublicKey */
       constructor();

       /**
        * @param {Uint8Array} pub_edward
        * @param {Uint8Array} pub_curve
        * @returns {keys.PublicKey}
        */
       static new(pub_edward: Uint8Array, pub_curve: Uint8Array): keys.PublicKey;

       /**
        * This function can be used to verify a message signature.
        *
        * @param {Uint8Array} signature - The signature to verify
        * @param {string} message - The message from which the signature was computed.
        * @returns {boolean} `true` if the signature is valid, `false` otherwise.
        */
       verify(signature: Uint8Array, message: string): boolean;

       /** @returns {string} */
       fingerprint(): string;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {keys.PublicKey}
        */
       static decode(d: CBOR.Decoder): keys.PublicKey;

   }

   /** @class SecretKey */
   class SecretKey {
       /** @class SecretKey */
       constructor();

       /**
        * @param {Uint8Array} sec_edward
        * @param {Uint8Array} sec_curve
        * @returns {*}
        */
       static new(sec_edward: Uint8Array, sec_curve: Uint8Array): any;

       /**
        * This function can be used to compute a message signature.
        *
        * @param {string} message - Message to be signed
        * @returns {Uint8Array} - A message signature
        */
       sign(message: string): Uint8Array;

       /**
        * This function can be used to compute a shared secret given a user's secret key and another
        * user's public key.
        *
        * @param {keys.PublicKey} public_key - Another user's public key
        * @returns {Uint8Array} Array buffer view of the computed shared secret
        */
       shared_secret(public_key: keys.PublicKey): Uint8Array;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {keys.SecretKey}
        */
       static decode(d: CBOR.Decoder): keys.SecretKey;

   }

}

/** @module message */
module message {
   /** @extends Message */
   class CipherMessage extends Message {
       /** @extends Message */
       constructor();

       /**
        * @param {message.SessionTag} session_tag
        * @param {number} counter
        * @param {number} prev_counter
        * @param {keys.PublicKey} ratchet_key
        * @param {Uint8Array} cipher_text
        * @returns {message.CipherMessage}
        */
       static new(session_tag: message.SessionTag, counter: number, prev_counter: number, ratchet_key: keys.PublicKey, cipher_text: Uint8Array): message.CipherMessage;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {message.CipherMessage}
        */
       static decode(d: CBOR.Decoder): message.CipherMessage;

   }

   /** @class Envelope */
   class Envelope {
       /** @class Envelope */
       constructor();

       /**
        * @param {derived.MacKey} mac_key
        * @param {message.Message} message
        * @returns {message.Envelope}
        */
       static new(mac_key: derived.MacKey, message: message.Message): message.Envelope;

       /**
        * @param {derived.MacKey} mac_key
        * @returns {boolean}
        */
       verify(mac_key: derived.MacKey): boolean;

       /** @returns {ArrayBuffer} The serialized message envelope */
       serialise(): ArrayBuffer;

       /**
        * @param {ArrayBuffer} buf
        * @returns {message.Envelope}
        */
       static deserialise(buf: ArrayBuffer): message.Envelope;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {message.Envelope}
        */
       static decode(d: CBOR.Decoder): message.Envelope;

   }

   /** @class Message */
   class Message {
       /** @class Message */
       constructor();

       /** @returns {ArrayBuffer} */
       serialise(): ArrayBuffer;

       /**
        * @param {ArrayBuffer} buf
        * @returns {message.CipherMessage|message.PreKeyMessage}
        */
       static deserialise(buf: ArrayBuffer): (message.CipherMessage|message.PreKeyMessage);

   }

   /** @extends Message */
   class PreKeyMessage extends Message {
       /** @extends Message */
       constructor();

       /**
        * @param {number} prekey_id
        * @param {keys.PublicKey} base_key
        * @param {keys.IdentityKey} identity_key
        * @param {message.CipherMessage} message
        * @returns {message.PreKeyMessage}
        */
       static new(prekey_id: number, base_key: keys.PublicKey, identity_key: keys.IdentityKey, message: message.CipherMessage): message.PreKeyMessage;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {message.PreKeyMessage}
        */
       static decode(d: CBOR.Decoder): message.PreKeyMessage;

   }

   /** @class SessionTag */
   class SessionTag {
       /** @class SessionTag */
       constructor();

       /** @returns {message.SessionTag} */
       static new(): message.SessionTag;

       /** @returns {string} */
       toString(): string;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {message.SessionTag}
        */
       static decode(d: CBOR.Decoder): message.SessionTag;

   }

}

/** @module session */
module session {
   /** @class ChainKey */
   class ChainKey {
       /** @class ChainKey */
       constructor();

       /**
        * @param {derived.MacKey} key - Mac Key generated by derived secrets
        * @param {number} counter
        * @returns {session.ChainKey}
        */
       static from_mac_key(key: derived.MacKey, counter: number): session.ChainKey;

       /** @returns {session.ChainKey} */
       next(): session.ChainKey;

       /** @returns {session.MessageKeys} */
       message_keys(): session.MessageKeys;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {session.ChainKey}
        */
       static decode(d: CBOR.Decoder): session.ChainKey;

   }

   /** @class MessageKeys */
   class MessageKeys {
       /** @class MessageKeys */
       constructor();

       /**
        * @param {derived.CipherKey} cipher_key
        * @param {derived.MacKey} mac_key
        * @param {number} counter
        * @returns {session.MessageKeys}
        */
       static new(cipher_key: derived.CipherKey, mac_key: derived.MacKey, counter: number): session.MessageKeys;

       /**
        * @returns {Uint8Array}
        * @private
        */
       private _counter_as_nonce(): Uint8Array;

       /**
        * @param {string|Uint8Array} plaintext
        * @returns {Uint8Array}
        */
       encrypt(plaintext: (string|Uint8Array)): Uint8Array;

       /**
        * @param {Uint8Array} ciphertext
        * @returns {Uint8Array}
        */
       decrypt(ciphertext: Uint8Array): Uint8Array;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {session.MessageKeys}
        */
       static decode(d: CBOR.Decoder): session.MessageKeys;

   }

   /** @class PreKeyStore */
   class PreKeyStore {
       /** @class PreKeyStore */
       constructor();

       /**
        * @param {number} prekey_id
        * @returns {void}
        */
       get_prekey(prekey_id: number): void;

       /**
        * @param {number} prekey_id
        * @returns {void}
        */
       remove(prekey_id: number): void;

   }

   /** @class RecvChain */
   class RecvChain {
       /** @class RecvChain */
       constructor();

       /**
        * @param {session.ChainKey} chain_key
        * @param {keys.PublicKey} public_key
        * @returns {message.PreKeyMessage}
        */
       static new(chain_key: session.ChainKey, public_key: keys.PublicKey): message.PreKeyMessage;

       /**
        * @param {message.Envelope} envelope
        * @param {message.CipherMessage} msg
        * @returns {Uint8Array}
        */
       try_message_keys(envelope: message.Envelope, msg: message.CipherMessage): Uint8Array;

       /**
        * @param {message.CipherMessage} msg
        * @returns {Array<session.ChainKey>|session.MessageKeys}
        */
       stage_message_keys(msg: message.CipherMessage): (session.ChainKey[]|session.MessageKeys);

       /**
        * @param {Array<session.MessageKeys>} keys
        * @returns {void}
        */
       commit_message_keys(keys: session.MessageKeys[]): void;

       /**
        * @param {CBOR.Encoder} e
        * @returns {Array<CBOR.Encoder>}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder[];

       /**
        * @param {CBOR.Decoder} d
        * @returns {session.RecvChain}
        */
       static decode(d: CBOR.Decoder): session.RecvChain;

       /** @type {number} */
       static MAX_COUNTER_GAP: number;

   }

   /** @class RootKey */
   class RootKey {
       /** @class RootKey */
       constructor();

       /**
        * @param {derived.CipherKey} cipher_key - Cipher key generated by derived secrets
        * @returns {session.RootKey}
        */
       static from_cipher_key(cipher_key: derived.CipherKey): session.RootKey;

       /**
        * @param {keys.KeyPair} ours - Our key pair
        * @param {keys.PublicKey} theirs - Their public key
        * @returns {Array<session.RootKey|session.ChainKey>}
        */
       dh_ratchet(ours: keys.KeyPair, theirs: keys.PublicKey): (session.RootKey|session.ChainKey)[];

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {session.RootKey}
        */
       static decode(d: CBOR.Decoder): session.RootKey;

   }

   /** @class SendChain */
   class SendChain {
       /** @class SendChain */
       constructor();

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {session.SendChain}
        */
       static decode(d: CBOR.Decoder): session.SendChain;

   }

   /** @class Session */
   class Session {
       /** @class Session */
       constructor();

       /**
        * @returns {number}
        */
       static MAX_RECV_CHAINS: any;

       /**
        * @returns {number}
        */
       static MAX_SESSION_STATES: any;

       /**
        * @param {keys.IdentityKeyPair} local_identity - Alice's Identity Key Pair
        * @param {keys.PreKeyBundle} remote_pkbundle - Bob's Pre-Key Bundle
        */
       static init_from_prekey(local_identity: keys.IdentityKeyPair, remote_pkbundle: keys.PreKeyBundle): void;

       /**
        * @param {keys.IdentityKeyPair} our_identity
        * @param {session.PreKeyStore} prekey_store
        * @param {message.Envelope} envelope
        * @returns {Promise}
        */
       static init_from_message(our_identity: keys.IdentityKeyPair, prekey_store: session.PreKeyStore, envelope: message.Envelope): Promise;

       /**
        * @param {session.PreKeyStore} pre_key_store
        * @param {message.PreKeyMessage} pre_key_message
        * @returns {Promise}
        * @private
        */
       private _new_state(pre_key_store: session.PreKeyStore, pre_key_message: message.PreKeyMessage): Promise;

       /**
        * @param {message.SessionTag} tag
        * @param {session.SessionState} state
        * @returns {boolean}
        * @private
        */
       private _insert_session_state(tag: message.SessionTag, state: session.SessionState): boolean;

       /**
        * @returns {void}
        * @private
        */
       private _evict_oldest_session_state(): void;

       /** @returns {keys.PublicKey} */
       get_local_identity(): keys.PublicKey;

       /**
        * @param {String|Uint8Array} plaintext - The plaintext which needs to be encrypted
        * @return {Promise<message.Envelope>} Encrypted message
        */
       encrypt(plaintext: (String|Uint8Array)): Promise<message.Envelope>;

       /**
        * @param {session.PreKeyStore} prekey_store
        * @param {message.Envelope} envelope
        * @returns {Promise}
        */
       decrypt(prekey_store: session.PreKeyStore, envelope: message.Envelope): Promise;

       /**
        * @param {message.Envelope} envelope
        * @param {message.Message} msg
        * @param {session.PreKeyStore} prekey_store
        * @returns {Promise}
        * @private
        */
       private _decrypt_prekey_message(envelope: message.Envelope, msg: message.Message, prekey_store: session.PreKeyStore): Promise;

       /**
        * @param {message.Envelope} envelope
        * @param {message.Message} msg
        * @returns {string}
        * @private
        */
       private _decrypt_cipher_message(envelope: message.Envelope, msg: message.Message): string;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {keys.IdentityKeyPair} local_identity
        * @param {CBOR.Decoder} d
        * @returns {session.Session}
        */
       static decode(local_identity: keys.IdentityKeyPair, d: CBOR.Decoder): session.Session;

   }

   /** @class SessionState */
   class SessionState {
       /** @class SessionState */
       constructor();

       /**
        * @param {keys.IdentityKeyPair} alice_identity_pair
        * @param {keys.PublicKey} alice_base
        * @param {keys.PreKeyBundle} bob_pkbundle
        * @returns {session.SessionState}
        */
       static init_as_alice(alice_identity_pair: keys.IdentityKeyPair, alice_base: keys.PublicKey, bob_pkbundle: keys.PreKeyBundle): session.SessionState;

       /**
        * @param {keys.IdentityKeyPair} bob_ident
        * @param {keys.KeyPair} bob_prekey
        * @param {keys.IdentityKey} alice_ident
        * @param {keys.PublicKey} alice_base
        * @returns {session.SessionState}
        */
       static init_as_bob(bob_ident: keys.IdentityKeyPair, bob_prekey: keys.KeyPair, alice_ident: keys.IdentityKey, alice_base: keys.PublicKey): session.SessionState;

       /**
        * @param {keys.KeyPair} ratchet_key
        * @returns {void}
        */
       ratchet(ratchet_key: keys.KeyPair): void;

       /**
        * @param {keys.IdentityKey} identity_key - Public identity key of the local identity key pair
        * @param {Array<number>} pending - Pending pre-key
        * @param {message.SessionTag} tag - Session tag
        * @param {string|Uint8Array} plaintext - The plaintext to encrypt
        * @returns {message.Envelope}
        */
       encrypt(identity_key: keys.IdentityKey, pending: number[], tag: message.SessionTag, plaintext: (string|Uint8Array)): message.Envelope;

       /**
        * @param {message.Envelope} envelope
        * @param {message.CipherMessage} msg
        * @returns {Uint8Array}
        */
       decrypt(envelope: message.Envelope, msg: message.CipherMessage): Uint8Array;

       /** @returns {ArrayBuffer} */
       serialise(): ArrayBuffer;

       /**
        * @param {CBOR.Encoder} e
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param {CBOR.Decoder} d
        * @returns {session.SessionState}
        */
       static decode(d: CBOR.Decoder): session.SessionState;

   }

}

/** @module util */
module util {
   /**
    * Concatenates array buffers (usually 8-bit unsigned).
    */
   const ArrayUtil: any;

   /** @class RandomUtil */
   class RandomUtil {
       /** @class RandomUtil */
       constructor();

       /** @returns {Uint8Array} */
       random_bytes(): Uint8Array;

   }

}

