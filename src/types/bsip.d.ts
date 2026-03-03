/**
 * Type definitions for bsip
 * SipHash-2-4 implementation from bcoin-org
 */

declare module 'bsip' {
  /**
   * Javascript siphash 2-4 implementation.
   * @param data - Input data buffer
   * @param key - 128 bit (16 byte) key buffer
   * @returns Array of [hi, lo] where hi and lo are signed 32-bit integers representing a 64-bit result
   */
  export function siphash(data: Buffer, key: Buffer): [number, number];

  /**
   * Javascript siphash 2-4 implementation (32 bit ints).
   * @param num - Input number
   * @param key - 128 bit (16 byte) key buffer
   * @returns 32-bit result
   */
  export function siphash32(num: number, key: Buffer): number;

  /**
   * Javascript siphash 2-4 implementation (64 bit ints).
   * @param hi - High 32 bits
   * @param lo - Low 32 bits
   * @param key - 128 bit (16 byte) key buffer
   * @returns Array of [hi, lo]
   */
  export function siphash64(hi: number, lo: number, key: Buffer): [number, number];

  /**
   * Javascript siphash 2-4 implementation (32 bit ints with a 256 bit key).
   * @param num - Input number
   * @param key - 256 bit (32 byte) key buffer
   * @returns 32-bit result
   */
  export function siphash32k256(num: number, key: Buffer): number;

  /**
   * Javascript siphash 2-4 implementation (64 bit ints with a 256 bit key).
   * @param hi - High 32 bits
   * @param lo - Low 32 bits
   * @param key - 256 bit (32 byte) key buffer
   * @returns Array of [hi, lo]
   */
  export function siphash64k256(hi: number, lo: number, key: Buffer): [number, number];

  /**
   * Javascript siphash 2-4 implementation plus 128 bit reduction by a modulus.
   * @param data - Input data buffer
   * @param key - 128 bit (16 byte) key buffer
   * @param mhi - Modulus high bits
   * @param mlo - Modulus low bits
   * @returns Array of [hi, lo]
   */
  export function sipmod(data: Buffer, key: Buffer, mhi: number, mlo: number): [number, number];
}
