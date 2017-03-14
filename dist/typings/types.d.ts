/**
 * @class CipherKey
 */
declare class CipherKey {
   /**
    * @class CipherKey
    */
   constructor();

   /**
    * @param key {Uint8Array}
    * @returns {MacKeyga}
    */
   static new(key: Uint8Array): MacKeyga;

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
    * @returns {CipherKey}
    */
   static decode(d: CBOR.Encoder): CipherKey;

}

/**
 * @class DerivedSecrets
 */
declare class DerivedSecrets {
   /**
    * @class DerivedSecrets
    */
   constructor();

   /**
    * @param input {Array<number>}
    * @param salt {Uint8Array}
    * @param info {string}
    * @returns {DerivedSecrets}
    */
   static kdf(input: number[], salt: Uint8Array, info: string): DerivedSecrets;

   /**
    * @param input {Array<number>} Initial key material (usually the Master Key) in byte array format
    * @param info {string} Key Derivation Data
    * @returns {DerivedSecrets}
    */
   static kdf_without_salt(input: number[], info: string): DerivedSecrets;

}

/**
 * @class MacKey
 * @public
 */
declare class MacKey {
   /**
    * @class MacKey
    * @public
    */
   constructor();

   /**
    * @param msg {string|Uint8Array}
    * Hash-based message authentication code
    */
   sign(msg: (string|Uint8Array)): void;

   /**
    * @param signature {Uint8Array}
    * @param msg {Array<number>}
    * @returns {boolean}
    */
   verify(signature: Uint8Array, msg: number[]): boolean;

   /**
    *
    * @param d {CBOR.Decoder}
    * @returns {MacKey}
    */
   static decode(d: CBOR.Decoder): MacKey;

}

/** @namespace derived */
declare module derived {
}

/** @namespace errors */
declare module errors {
}

/** @namespace keys */
declare module keys {
}

/** @namespace message */
declare module message {
}

/** @namespace session */
declare module session {
}

