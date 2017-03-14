/**
 * @class
 * @public
 */
declare class CipherKey {
   /**
    * @class
    * @public
    */
   constructor();

   /**
    * @param key {Uint8Array}
    * @returns {CipherKey}
    */
   static new(key: Uint8Array): CipherKey;

}

/**
 * @class
 * @public
 * @type {DerivedSecrets}
 */
declare class DerivedSecrets {
   /**
    * @class
    * @public
    * @type {DerivedSecrets}
    */
   constructor();

   /**
    *
    * @param input {Array<number>}
    * @param salt {Array<number>}
    * @param info {string}
    * @public
    * @returns {DerivedSecrets}
    */
   public static kdf(input: number[], salt: number[], info: string): DerivedSecrets;

   /**
    * @param input {Array<number>} Initial key material (usually the Master Key) in byte array format
    * @param info {string} Key Derivation Data
    * @public
    * @returns {DerivedSecrets}
    */
   public static kdf_without_salt(input: number[], info: string): DerivedSecrets;

}

/**
 * @class
 * @public
 * @type {MacKey}
 */
declare class MacKey {
   /**
    * @class
    * @public
    * @type {MacKey}
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

