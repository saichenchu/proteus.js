/**
 * @class
 */
declare class TestClass {
    /**
     * @param arr {Uint8Array}
     * @returns {Uint8Array}
     */
    testReturn(arr: any): any;

}

/**
 * @class
 * @public
 */
declare class CipherKey {
    constructor();

    /**
     * @param key {Uint8Array}
     * @returns {CipherKey}
     */
    static new(key: any): CipherKey;

}

/**
 * @class
 * @public
 * @type {DerivedSecrets}
 */
declare class DerivedSecrets {
    constructor();

    /**
     * @param input {Array<number>}
     * @param salt {Array<number>}
     * @param info {string}
     * @public
     * @returns {DerivedSecrets}
     */
    static kdf(input: number[], salt: number[], info: string): DerivedSecrets;

    /**
     * @param input {Array<number>} Initial key material (usually the Master Key) in byte array format
     * @param info {string} Key Derivation Data
     * @public
     * @returns {DerivedSecrets}
     */
    static kdf_without_salt(input: number[], info: string): DerivedSecrets;

}

/**
 * @class
 * @public
 * @type {MacKey}
 */
declare class MacKey {
    constructor();

    /**
     * @param msg {string|Array<number>}
     * Hash-based message authentication code
     */
    sign(msg: string | number[]): void;

    /**
     * @param signature {Array<number>}
     * @param msg {Array<number>}
     * @returns {boolean}
     */
    verify(signature: number[], msg: number[]): boolean;

    /**
     * @param d {*}
     * @returns {MacKey}
     */
    static decode(d: any): MacKey;

}

