// The registry's dedup key: every spelling of one seed files under one
// facade. Pure: no facade is built.

import { describe, expect, it } from "vitest";

import { walletRegistryKey } from "../src/index.ts";

const SEED_HEX = "5bdb535372994e3695f62f82599763a84c6a99b1f48d46ae376e293faedf8c6b";

describe("walletRegistryKey", () => {
  /** One spelling of the seed above. */
  interface SpellingCase {
    readonly name: string;
    readonly seed: string;
  }

  const SPELLINGS: readonly SpellingCase[] = [
    { name: "bare lowercase hex", seed: SEED_HEX },
    { name: "0x-prefixed hex", seed: `0x${SEED_HEX}` },
    { name: "upper-case hex", seed: SEED_HEX.toUpperCase() },
    { name: "hex with surrounding whitespace", seed: `  ${SEED_HEX}\n` },
  ];

  it.each(SPELLINGS)("files $name under the normalised hex", ({ seed }) => {
    expect(walletRegistryKey(seed)).toBe(SEED_HEX);
  });

  it("files a mnemonic under its 64-byte derived seed", () => {
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    expect(walletRegistryKey(mnemonic)).toMatch(/^[0-9a-f]{128}$/);
  });

  it("refuses something that is neither hex nor a mnemonic", () => {
    expect(() => walletRegistryKey("not a seed")).toThrow(/Not a valid BIP-39 mnemonic/);
  });
});
