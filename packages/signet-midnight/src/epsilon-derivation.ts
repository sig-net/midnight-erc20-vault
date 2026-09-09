// Epsilon key derivation: contract address + path -> derived EVM account.
//
// This belongs in github.com/sig-net/signet.js, kept here until upstreamed.
//
// v2.0.0 (COLON-separated) is the only scheme the MPC answers: the Compact
// contracts assert `keyVersion >= 1`, which selects v2.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { computeAddress, keccak256, SigningKey, toUtf8Bytes } from "ethers";

import { bigintToBytes32BE, bytesToBigintBE, stripHexPrefix } from "./byte-codecs.ts";
import { SECP256K1_ORDER, type Secp256k1Point } from "./ecdsa-attestation.ts";

/**
 * Prefix for the MPC's v2.0.0 epsilon derivation.
 */
export const EPSILON_DERIVATION_PREFIX = "sig.network v2.0.0 epsilon derivation";

/**
 * Fixed Midnight derivation domain, independent of the connected network.
 */
export const MIDNIGHT_MAINNET_CHAIN_ID = "midnight:mainnet";

/**
 * Literal response-key path, used with each client contract's address.
 */
export const MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH = "midnight response key";

/**
 * Normalise a contract address for derivation.
 *
 * @param contractAddress - The Midnight contract address, with or without `0x`.
 * @returns The address as lowercase hex with no prefix.
 */
function normaliseRequesterAddress(contractAddress: string): string {
  return stripHexPrefix(contractAddress).toLowerCase();
}

/**
 * Derive the MPC signing address for a Midnight contract and path.
 *
 * @param mpcSecp256k1PubkeyHex - Root public key in compressed or uncompressed hex.
 * @param contractAddress - Requesting contract address; prefix and case are normalised.
 * @param path - Opaque path string. For ledger requests, use lowercase hex of all
 *   32 path bytes, without a prefix or trimming (see {@link bytesToHex}).
 * @returns The derived EVM address as a 0x-prefixed EIP-55 checksummed string.
 */
export function deriveEvmAddress(
  mpcSecp256k1PubkeyHex: string,
  contractAddress: string,
  path: string,
): string {
  const derivedPoint = deriveChildPoint(
    mpcSecp256k1PubkeyHex,
    normaliseRequesterAddress(contractAddress),
    path,
  );
  return computeAddress(`0x${derivedPoint.toHex(false)}`);
}

/**
 * Hash `<prefix>:midnight:mainnet:<requester>:<path>` modulo the secp256k1 order.
 *
 * @param requester - Requester string, used verbatim without normalisation.
 * @param path - The derivation path string.
 * @returns The epsilon scalar, in `[0, n)`.
 */
export function deriveEpsilon(requester: string, path: string): bigint {
  const fullPath = `${EPSILON_DERIVATION_PREFIX}:${MIDNIGHT_MAINNET_CHAIN_ID}:${requester}:${path}`;
  return BigInt(keccak256(toUtf8Bytes(fullPath))) % SECP256K1_ORDER;
}

/**
 * Derive the child public key as a noble curve point (internal shape).
 *
 * @param mpcSecp256k1PubkeyHex - The MPC root public key in SEC1 hex.
 * @param requester - The normalised requester address.
 * @param path - The derivation path component.
 * @returns The derived child point on secp256k1.
 */
function deriveChildPoint(mpcSecp256k1PubkeyHex: string, requester: string, path: string) {
  const epsilon = deriveEpsilon(requester, path);
  const rootPubKeyHex = SigningKey.computePublicKey(mpcSecp256k1PubkeyHex, false);
  const rootPoint = secp256k1.Point.fromHex(rootPubKeyHex.slice(2));
  return epsilon === 0n ? rootPoint : rootPoint.add(secp256k1.Point.BASE.multiply(epsilon));
}

/**
 * Derive the response public key a client contract pins for attestation verification.
 *
 * @param mpcSecp256k1PubkeyHex - The MPC root secp256k1 public key as 0x-hex
 *   (compressed or uncompressed).
 * @param clientContractAddress - The client contract's Midnight address
 *   (`0x` prefix optional, case-insensitive).
 * @returns The response public key as a Compact-runtime `Secp256k1Point`.
 */
export function deriveMidnightResponseKey(
  mpcSecp256k1PubkeyHex: string,
  clientContractAddress: string,
): Secp256k1Point {
  const point = deriveChildPoint(
    mpcSecp256k1PubkeyHex,
    normaliseRequesterAddress(clientContractAddress),
    MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH,
  );
  return { x: point.x, y: point.y, identity: false };
}

/**
 * Derive a client's response secret key for signers and test harnesses.
 *
 * @param mpcRootSecretKey - The 32-byte MPC root secret key (big-endian).
 * @param clientContractAddress - The client contract's Midnight address
 *   (`0x` prefix optional, case-insensitive).
 * @returns The 32-byte response secret key (big-endian).
 * @throws {Error} If the root key is not 32 bytes or the derived scalar is 0.
 */
export function deriveMidnightResponseSecretKey(
  mpcRootSecretKey: Uint8Array,
  clientContractAddress: string,
): Uint8Array {
  if (mpcRootSecretKey.length !== 32) {
    throw new Error(`MPC root secret key must be 32 bytes, got ${String(mpcRootSecretKey.length)}`);
  }
  const root = bytesToBigintBE(mpcRootSecretKey);
  const epsilon = deriveEpsilon(
    normaliseRequesterAddress(clientContractAddress),
    MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH,
  );
  const child = (root + epsilon) % SECP256K1_ORDER;
  if (child === 0n) {
    throw new Error("derived response secret key is zero (invalid scalar)");
  }
  return bigintToBytes32BE(child);
}
