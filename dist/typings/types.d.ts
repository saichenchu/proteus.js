/** @module derived */
module derived {
   /** @class CipherKey */
   class CipherKey {
       /** @class CipherKey */
       constructor();

       /**
        * @param key {Uint8Array}
        * @returns {derived.MacKey}
        */
       static new(key: Uint8Array): derived.MacKey;

       /**
        * @param plaintext {ArrayBuffer|String|Uint8Array} The text to encrypt
        * @param nonce {Uint8Array} Counter as nonce
        * @returns {Uint8Array} Encrypted payload
        */
       encrypt(plaintext: (ArrayBuffer|String|Uint8Array), nonce: Uint8Array): Uint8Array;

       /**
        * @param ciphertext {Uint8Array}
        * @param nonce {Uint8Array}
        * @returns {Uint8Array}
        */
       decrypt(ciphertext: Uint8Array, nonce: Uint8Array): Uint8Array;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Encoder}
        * @returns {derived.CipherKey}
        */
       static decode(d: CBOR.Encoder): derived.CipherKey;

   }

   /** @class DerivedSecrets */
   class DerivedSecrets {
       /** @class DerivedSecrets */
       constructor();

       /**
        * @param input {Array<number>}
        * @param salt {Uint8Array}
        * @param info {string}
        * @returns {derived.DerivedSecrets}
        */
       static kdf(input: number[], salt: Uint8Array, info: string): derived.DerivedSecrets;

       /**
        * @param input {Array<number>} Initial key material (usually the Master Key) in byte array format
        * @param info {string} Key Derivation Data
        * @returns {derived.DerivedSecrets}
        */
       static kdf_without_salt(input: number[], info: string): derived.DerivedSecrets;

   }

   /** @class MacKey */
   class MacKey {
       /** @class MacKey */
       constructor();

       /**
        * @param key {Uint8Array} Mac Key in byte array format generated by derived secrets
        * @returns {derived.MacKey}
        */
       static new(key: Uint8Array): derived.MacKey;

       /**
        * Hash-based message authentication code
        * @param msg {string|Uint8Array}
        * @returns {Uint8Array}
        */
       sign(msg: (string|Uint8Array)): Uint8Array;

       /**
        * @param signature {Uint8Array}
        * @param msg {Uint8Array}
        * @returns {boolean}
        */
       verify(signature: Uint8Array, msg: Uint8Array): boolean;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
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
    */
   class ProteusError extends Error {
       /**
        * @class ProteusError
        * @extends Error
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
        * @param public_key {keys.IdentityKey}
        * @returns {keys.IdentityKey}
        */
       static new(public_key: keys.IdentityKey): keys.IdentityKey;

       /** @returns {string} */
       fingerprint(): string;

       /** @returns {string} */
       toString(): string;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
        * @returns {keys.IdentityKey}
        */
       static decode(d: CBOR.Decoder): keys.IdentityKey;

   }

   /** @class IndentityKeyPair */
   class IndentityKeyPair {
       /** @class IndentityKeyPair */
       constructor();

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

       /** @returns {key.KeyPair} */
       static new(): key.KeyPair;

       /**
        * @description Ed25519 keys can be converted to Curve25519 keys, so that the same key pair can be
        * used both for authenticated encryption (crypto_box) and for signatures (crypto_sign).
        * @param ed25519_key_pair {Uint8Array} Key pair based on Edwards-curve (Ed25519)
        * @returns {keys.SecretKey} Constructed private key
        * @see https://download.libsodium.org/doc/advanced/ed25519-curve25519.html
        */
       _construct_private_key(ed25519_key_pair: Uint8Array): keys.SecretKey;

       /**
        * @param ed25519_key_pair {libsodium.KeyPair} Key pair based on Edwards-curve (Ed25519)
        * @returns {keys.PublicKey} Constructed public key
        */
       _construct_public_key(ed25519_key_pair: libsodium.KeyPair): keys.PublicKey;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
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
        * @param pre_key_id {number}
        * @returns {keys.PreKey}
        */
       static new(pre_key_id: number): keys.PreKey;

       /** @returns {keys.PreKey} */
       static last_resort(): keys.PreKey;

       /**
        * @param start {number}
        * @param size {number}
        * @returns {Array<keys.PreKey>}
        */
       static generate_prekeys(start: number, size: number): keys.PreKey[];

       /** @returns {ArrayBuffer} */
       serialise(): ArrayBuffer;

       /**
        * @param buf {ArrayBuffer}
        * @returns {keys.PreKey}
        */
       static deserialise(buf: ArrayBuffer): keys.PreKey;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
        * @returns {keys.PreKey}
        */
       static decode(d: CBOR.Decoder): keys.PreKey;

       /**
        * @static
        * @type {number}
        */
       static MAX_PREKEY_ID: number;

   }

   /** @class PreKeyBundle */
   class PreKeyBundle {
       /** @class PreKeyBundle */
       constructor();

       /**
        * @param public_identity_key {keys.IdentityKey}
        * @param prekey {keys.PreKey}
        * @returns {keys.PreKeyBundle}
        */
       static new(public_identity_key: keys.IdentityKey, prekey: keys.PreKey): keys.PreKeyBundle;

       /**
        * @param identity_pair {keys.IdentityKeyPair}
        * @param prekey {keys.PreKey}
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
        * @param buf {ArrayBuffer}
        * @returns {keys.PreKeyBundle}
        */
       static deserialise(buf: ArrayBuffer): keys.PreKeyBundle;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
        * @returns {keys.PreKeyBundle}
        */
       static decode(d: CBOR.Decoder): keys.PreKeyBundle;

   }

   /** @class PublicKey */
   class PublicKey {
       /** @class PublicKey */
       constructor();

       /**
        * @param pub_edward {Uint8Array}
        * @param pub_curve {Uint8Array}
        * @returns {keys.PublicKey}
        */
       static new(pub_edward: Uint8Array, pub_curve: Uint8Array): keys.PublicKey;

       /**
        * This function can be used to verify a message signature.
        *
        * @param signature {Uint8Array} The signature to verify
        * @param message {string} The message from which the signature was computed.
        * @returns {boolean} `true` if the signature is valid, `false` otherwise.
        */
       verify(signature: Uint8Array, message: string): boolean;

       /** @returns {string} */
       fingerprint(): string;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
        * @returns {keys.PublicKey}
        */
       static decode(d: CBOR.Decoder): keys.PublicKey;

   }

   /** @class SecretKey */
   class SecretKey {
       /** @class SecretKey */
       constructor();

       /**
        * @param sec_edward {Uint8Array}
        * @param sec_curve {Uint8Array}
        * @returns {*}
        */
       static new(sec_edward: Uint8Array, sec_curve: Uint8Array): any;

       /**
        * This function can be used to compute a message signature.
        *
        * @param message {string} Message to be signed
        * @returns {Uint8Array} A message signature
        */
       sign(message: string): Uint8Array;

       /**
        * This function can be used to compute a shared secret given a user's secret key and another
        * user's public key.
        *
        * @param public_key {keys.PublicKey} Another user's public key
        * @returns {Uint8Array} Array buffer view of the computed shared secret
        */
       shared_secret(public_key: keys.PublicKey): Uint8Array;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
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
        * @param session_tag {message.SessionTag}
        * @param counter {number}
        * @param prev_counter {number}
        * @param ratchet_key {keys.PublicKey}
        * @param cipher_text {Uint8Array}
        * @returns {message.CipherMessage}
        */
       static new(session_tag: message.SessionTag, counter: number, prev_counter: number, ratchet_key: keys.PublicKey, cipher_text: Uint8Array): message.CipherMessage;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
        * @returns {message.CipherMessage}
        */
       static decode(d: CBOR.Decoder): message.CipherMessage;

   }

   /** @class Envelope */
   class Envelope {
       /** @class Envelope */
       constructor();

       /**
        * @param mac_key {derived.MacKey}
        * @param message {message.Message}
        * @returns {message.Envelope}
        */
       static new(mac_key: derived.MacKey, message: message.Message): message.Envelope;

       /**
        * @param mac_key {derived.MacKey}
        * @returns {boolean}
        */
       verify(mac_key: derived.MacKey): boolean;

       /** @returns {ArrayBuffer} The serialized message envelope */
       serialise(): ArrayBuffer;

       /**
        * @param buf {ArrayBuffer}
        * @returns {message.Envelope}
        */
       static deserialise(buf: ArrayBuffer): message.Envelope;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
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
        * @param buf {ArrayBuffer}
        * @returns {message.Message}
        */
       static deserialise(buf: ArrayBuffer): message.Message;

   }

   /** @extends Message */
   class PreKeyMessage extends Message {
       /** @extends Message */
       constructor();

       /**
        * @param prekey_id {number}
        * @param base_key {keys.PublicKey}
        * @param identity_key {keys.IdentityKey}
        * @param message {message.CipherMessage}
        * @returns {message.PreKeyMessage}
        */
       static new(prekey_id: number, base_key: keys.PublicKey, identity_key: keys.IdentityKey, message: message.CipherMessage): message.PreKeyMessage;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
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
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
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
        * @param key {derived.MacKey} Mac Key generated by derived secrets
        * @param counter {number}
        * @returns {session.ChainKey}
        */
       static from_mac_key(key: derived.MacKey, counter: number): session.ChainKey;

       /** @returns {session.ChainKey} */
       next(): session.ChainKey;

       /** @returns {session.MessageKeys} */
       message_keys(): session.MessageKeys;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
        * @returns {session.ChainKey}
        */
       static decode(d: CBOR.Decoder): session.ChainKey;

   }

   /** @class MessageKeys */
   class MessageKeys {
       /** @class MessageKeys */
       constructor();

       /**
        * @param cipher_key {derived.CipherKey}
        * @param mac_key {derived.MacKey}
        * @param counter {number}
        * @returns {session.MessageKeys}
        */
       static new(cipher_key: derived.CipherKey, mac_key: derived.MacKey, counter: number): session.MessageKeys;

       /**
        * @returns {Uint8Array}
        * @private
        */
       private _counter_as_nonce(): Uint8Array;

       /**
        * @param plaintext {string|Uint8Array}
        * @returns {Uint8Array}
        */
       encrypt(plaintext: (string|Uint8Array)): Uint8Array;

       /**
        * @param ciphertext {Uint8Array}
        * @returns {Uint8Array}
        */
       decrypt(ciphertext: Uint8Array): Uint8Array;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
        * @returns {session.MessageKeys}
        */
       static decode(d: CBOR.Decoder): session.MessageKeys;

   }

   /** @class PreKeyStore */
   class PreKeyStore {
       /** @class PreKeyStore */
       constructor();

       /** @param prekey_id {number} */
       get_prekey(prekey_id: number): void;

       /** @param prekey_id {number} */
       remove(prekey_id: number): void;

   }

   /** @class RecvChain */
   class RecvChain {
       /** @class RecvChain */
       constructor();

       /**
        * @param chain_key {session.ChainKey}
        * @param public_key {keys.PublicKey}
        * @returns {message.PreKeyMessage}
        */
       static new(chain_key: session.ChainKey, public_key: keys.PublicKey): message.PreKeyMessage;

       /**
        * @param envelope {message.Envelope}
        * @param msg {message.CipherMessage}
        * @returns {Uint8Array}
        */
       try_message_keys(envelope: message.Envelope, msg: message.CipherMessage): Uint8Array;

       /**
        * @param msg {message.CipherMessage}
        * @returns {Array<session.ChainKey>|session.MessageKeys}
        */
       stage_message_keys(msg: message.CipherMessage): (session.ChainKey[]|session.MessageKeys);

       /** @param keys {Array<session.MessageKeys>} */
       commit_message_keys(keys: session.MessageKeys[]): void;

       /**
        * @param e {CBOR.Encoder}
        * @returns {Array<CBOR.Encoder>}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder[];

       /**
        * @param d {CBOR.Decoder}
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
        * @param cipher_key {derived.CipherKey} Cipher key generated by derived secrets
        * @returns {session.RootKey}
        */
       static from_cipher_key(cipher_key: derived.CipherKey): session.RootKey;

       /**
        * @param ours {keys.KeyPair} Our key pair
        * @param theirs {keys.PublicKey} Their public key
        * @returns {Array<session.RootKey|session.ChainKey>}
        */
       dh_ratchet(ours: keys.KeyPair, theirs: keys.PublicKey): (session.RootKey|session.ChainKey)[];

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
        * @returns {session.RootKey}
        */
       static decode(d: CBOR.Decoder): session.RootKey;

   }

   /** @class SendChain */
   class SendChain {
       /** @class SendChain */
       constructor();

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

   }

   /** @class Session */
   class Session {
       /** @class Session */
       constructor();

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /** @type {number} */
       static MAX_RECV_CHAINS: number;

       /** @type {number} */
       static MAX_SESSION_STATES: number;

   }

   /** @class SessionState */
   class SessionState {
       /** @class SessionState */
       constructor();

       /**
        * @param alice_identity_pair {keys.IdentityKeyPair}
        * @param alice_base {keys.PublicKey}
        * @param bob_pkbundle {keys.PreKeyBundle}
        * @returns {session.SessionState}
        */
       static init_as_alice(alice_identity_pair: keys.IdentityKeyPair, alice_base: keys.PublicKey, bob_pkbundle: keys.PreKeyBundle): session.SessionState;

       /**
        * @param bob_ident {keys.IdentityKeyPair}
        * @param bob_prekey {keys.KeyPair}
        * @param alice_ident {keys.IdentityKey}
        * @param alice_base {keys.PublicKey}
        * @returns {session.SessionState}
        */
       static init_as_bob(bob_ident: keys.IdentityKeyPair, bob_prekey: keys.KeyPair, alice_ident: keys.IdentityKey, alice_base: keys.PublicKey): session.SessionState;

       /** @param ratchet_key {keys.KeyPair} */
       ratchet(ratchet_key: keys.KeyPair): void;

       /**
        * @param identity_key {keys.IdentityKey} Public identity key of the local identity key pair
        * @param pending {Array<number>} Pending pre-key
        * @param tag {message.SessionTag} Session tag
        * @param plaintext {string|Uint8Array} The plaintext to encrypt
        * @returns {message.Envelope}
        */
       encrypt(identity_key: keys.IdentityKey, pending: number[], tag: message.SessionTag, plaintext: (string|Uint8Array)): message.Envelope;

       /**
        * @param envelope {message.Envelope}
        * @param msg {message.CipherMessage}
        * @returns {Uint8Array}
        */
       decrypt(envelope: message.Envelope, msg: message.CipherMessage): Uint8Array;

       /** @returns {ArrayBuffer} */
       serialise(): ArrayBuffer;

       /**
        * @param e {CBOR.Encoder}
        * @returns {CBOR.Encoder}
        */
       encode(e: CBOR.Encoder): CBOR.Encoder;

       /**
        * @param d {CBOR.Decoder}
        * @returns {session.SessionState}
        */
       static decode(d: CBOR.Decoder): session.SessionState;

   }

}

