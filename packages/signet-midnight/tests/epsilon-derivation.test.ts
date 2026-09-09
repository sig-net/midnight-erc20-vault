// Mainnet vectors: sig-net/mpc@d04faa90078e9fd71ce0523562f3be80311a910f,
// signet-crypto/src/kdf.rs: derive_epsilon_midnight(1, ...) and derive_key.
// Other domains use independently constructed v2 vectors.

import { describe, expect, it } from "vitest";

import {
  asciiPadded,
  bytesToHex,
  deriveEpsilon,
  deriveEvmAddress,
  deriveMidnightResponseKey,
  MIDNIGHT_TESTNET_CHAIN_ID,
  parseSecp256k1PublicKey,
} from "../src/index.ts";
import { deriveMidnightResponseSecretKey, secp256k1PublicKeyOf } from "../src/testing.ts";

// The compressed secp256k1 public key of the fixed MPC root key 9e3b…9e0f
// from the golden-vector run (also asserted in mpc-keys.test.ts).
const MPC_PUBKEY = "0x0281e037488c6e708c5a28c8bc2e43b7a704f3a869bd129fb6511bcc58e98db243";
const CONTRACT_ADDRESS = "0200e5e9a4f3d1b2c6a7889900aabbccddeeff00112233445566778899aabbccdd";
const COMMITMENT_HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

interface Case {
  name: string;
  path: string;
  chainId: string | undefined;
  expected: string;
}

const CASES: Case[] = [
  {
    name: "explicit testnet domain retains its meaning",
    path: "vault",
    chainId: MIDNIGHT_TESTNET_CHAIN_ID,
    expected: "0x607622ceB3b0f430EaC738B8FeBD577F6d11D37F",
  },
  {
    name: "vault path, default midnight:mainnet chain id",
    path: "vault",
    chainId: undefined,
    expected: "0x3d4C6Ebe9016168397F6E15De5fd2412e2FB222C",
  },
  {
    name: "user commitment-hex path, default chain id",
    path: COMMITMENT_HEX,
    chainId: undefined,
    expected: "0x286BC9Fb1CfBaC876471ee2aF17976b4336Adb65",
  },
  {
    name: "explicit non-default chain id changes the derivation",
    path: "vault",
    chainId: "eip155:11155111",
    expected: "0x11F95e6098FC53fD106506F8b42726990b176348",
  },
];

describe("deriveEvmAddress", () => {
  it.each(CASES)("$name", ({ path, chainId, expected }) => {
    const address = chainId
      ? deriveEvmAddress(MPC_PUBKEY, CONTRACT_ADDRESS, path, chainId)
      : deriveEvmAddress(MPC_PUBKEY, CONTRACT_ADDRESS, path);
    expect(address).toBe(expected);
  });

  it("accepts the uncompressed form of the same root public key", () => {
    // 04 || x || y expansion of MPC_PUBKEY: same key, same derived address.
    const uncompressed =
      "0x0481e037488c6e708c5a28c8bc2e43b7a704f3a869bd129fb6511bcc58e98db243" +
      "4fd9fffb61ad2ff6c6423cbd51e2d8d9535fef116d48dfeedce3276db6a53446";
    expect(deriveEvmAddress(uncompressed, CONTRACT_ADDRESS, "vault")).toBe(
      "0x3d4C6Ebe9016168397F6E15De5fd2412e2FB222C",
    );
  });

  it("rejects a malformed public key", () => {
    expect(() => deriveEvmAddress("0x1234", CONTRACT_ADDRESS, "vault")).toThrow();
  });

  it("normalises the requester: 0x prefix and case do not change the address", () => {
    const canonical = deriveEvmAddress(MPC_PUBKEY, CONTRACT_ADDRESS, "vault");
    expect(deriveEvmAddress(MPC_PUBKEY, `0x${CONTRACT_ADDRESS}`, "vault")).toBe(canonical);
    expect(deriveEvmAddress(MPC_PUBKEY, CONTRACT_ADDRESS.toUpperCase(), "vault")).toBe(canonical);
  });
});

// Cross-implementation vectors for accounts derived from an on-ledger
// record's `path: Bytes<32>`: the MPC renders the path as the lowercase hex
// of the FULL 32 bytes, verbatim (sig-net/mpc chain-midnight convert.rs), so
// the TS side must reach the same address via bytesToHex. Golden addresses
// come from the Rust implementation cited above.
describe("deriveEvmAddress from record path bytes (MPC hex rendering)", () => {
  interface PathBytesCase {
    name: string;
    pathBytes: Uint8Array;
    expectedPathHex: string;
    expectedAddress: string;
  }

  const PATH_BYTES_CASES: PathBytesCase[] = [
    {
      // A text-style path: the zero padding is part of the rendering.
      name: "padded ascii literal pad(32, 'caller-path')",
      pathBytes: asciiPadded("caller-path", 32),
      expectedPathHex: "63616c6c65722d70617468000000000000000000000000000000000000000000",
      expectedAddress: "0x26c05D12f8147C8428dcda4d263736062BDE5eA4",
    },
    {
      // A commitment-style path: invalid UTF-8, an interior NUL and a
      // trailing zero byte, all rendered verbatim (the rendering is total).
      name: "raw commitment bytes with interior and trailing NULs",
      pathBytes: new Uint8Array([
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0xff, 0xfe, 0x00, 0x5c, 0x6d, 0x7e, 0x8f,
        0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e,
        0x8f, 0x00,
      ]),
      expectedPathHex: "a1b2c3d4e5f60718fffe005c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f00",
      expectedAddress: "0xA05732714EBC6c2366F2876CC817c9998efDc789",
    },
  ];

  it.each(PATH_BYTES_CASES)("$name", ({ pathBytes, expectedPathHex, expectedAddress }) => {
    const pathHex = bytesToHex(pathBytes);
    expect(pathHex).toBe(expectedPathHex);
    expect(deriveEvmAddress(MPC_PUBKEY, CONTRACT_ADDRESS, pathHex)).toBe(expectedAddress);
  });
});

// The root secret key behind MPC_PUBKEY (the mpc-keys golden root key).
const MPC_ROOT_SECRET = Uint8Array.from(
  Buffer.from("9e3b2f8d1c4a5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f", "hex"),
);
const CLIENT_ADDRESS = CONTRACT_ADDRESS;

describe("deriveMidnightResponseKey / deriveMidnightResponseSecretKey", () => {
  it("matches the Rust response-key vector for the existing test root", () => {
    const expected = parseSecp256k1PublicKey(
      "033bd4c0204cec4b87d1d3e15f75051dba7e1e80ffaa3c83853192a41bc18ed8c2",
    );
    expect(deriveMidnightResponseKey(MPC_PUBKEY, CLIENT_ADDRESS)).toEqual(expected);
    expect(
      secp256k1PublicKeyOf(deriveMidnightResponseSecretKey(MPC_ROOT_SECRET, CLIENT_ADDRESS)),
    ).toEqual(expected);
  });

  it("secret and public derivations agree: pub(secret) == derived public key", () => {
    const secret = deriveMidnightResponseSecretKey(MPC_ROOT_SECRET, CLIENT_ADDRESS);
    expect(secp256k1PublicKeyOf(secret)).toEqual(
      deriveMidnightResponseKey(MPC_PUBKEY, CLIENT_ADDRESS),
    );
  });

  it("is not the root key", () => {
    expect(deriveMidnightResponseKey(MPC_PUBKEY, CLIENT_ADDRESS)).not.toEqual(
      secp256k1PublicKeyOf(MPC_ROOT_SECRET),
    );
  });

  it("is scoped per client contract: a different address derives a different key", () => {
    const other = "ff".repeat(32);
    expect(deriveMidnightResponseKey(MPC_PUBKEY, other)).not.toEqual(
      deriveMidnightResponseKey(MPC_PUBKEY, CLIENT_ADDRESS),
    );
  });

  it("normalises the address: 0x prefix and case do not change the key", () => {
    const canonical = deriveMidnightResponseKey(MPC_PUBKEY, CLIENT_ADDRESS);
    expect(deriveMidnightResponseKey(MPC_PUBKEY, `0x${CLIENT_ADDRESS}`)).toEqual(canonical);
    expect(deriveMidnightResponseKey(MPC_PUBKEY, CLIENT_ADDRESS.toUpperCase())).toEqual(canonical);
  });

  it("rejects a root secret key that is not 32 bytes", () => {
    expect(() => deriveMidnightResponseSecretKey(new Uint8Array(31), CLIENT_ADDRESS)).toThrow(
      /32 bytes/,
    );
  });
});

// Finalized request (key version 1):
// 2a95e3ce147aad36e5130a36212f23229fc26d1436489eeb8b7f0e8a1f895f00.
describe("Rust Midnight derivation vectors for a finalized request", () => {
  const root = "0x02cb41bab8bc97121f4902514ca57a284f167b9239ecb8176831d1ef0fede87c61";
  const caller = "31c8a27a2695895ec40b491fedc5859aa2126cfb53f7e3d0fd0a24644d7d0478";
  const path = "2c7c21ecc735a55758c5a807139676ca3e26dba44afca9f89bd2de8cde91e000";

  it("matches the Rust epsilon without an explicit domain", () => {
    expect(deriveEpsilon(caller, path)).toBe(
      0x72fe94620a962f09f532cc35f222cbe6367dda1e3e919b4a6e210d05d227bf1dn,
    );
  });

  it("matches the Rust account address without an explicit domain", () => {
    expect(deriveEvmAddress(root, caller, path)).toBe("0xDC0D4c682AA48518E47a54D76B253258f01FdEb4");
  });

  it("matches the Rust response key using the literal response path", () => {
    expect(deriveMidnightResponseKey(root, caller)).toEqual(
      parseSecp256k1PublicKey("032f79a948af713852c136f8ad8ed5594dccfd731709ec108893dba9ebf37c9b5c"),
    );
  });
});
