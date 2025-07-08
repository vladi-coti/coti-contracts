import crypto from "crypto"

export function generateRandomNumber(numBytes: number): bigint {
    const bytes = crypto.randomBytes(numBytes)
    // Convert bytes to BigInt
    return BigInt('0x' + bytes.toString('hex'))
}
  