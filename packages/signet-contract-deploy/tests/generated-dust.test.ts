// The facade refusal a first-time dust registration can hit, parsed for the
// fee it names. Pure: no facade.

import { describe, expect, it } from "vitest";

import { requiredGeneratedDust } from "../src/index.ts";

describe("requiredGeneratedDust", () => {
  /** One thing the registration may throw, and the fee read from it. */
  interface ThrownCase {
    readonly name: string;
    readonly thrown: unknown;
    readonly fee: bigint | undefined;
  }

  const CASES: readonly ThrownCase[] = [
    {
      // The facade's verbatim refusal for a 2 NIGHT UTXO registered a minute after landing.
      name: "the facade's insufficient-generated-dust refusal",
      thrown: new Error(
        "Insufficient generated dust to cover registration fee (have 396816000000000, need 411384474481955). " +
          "Use WalletFacade.waitForGeneratedDust(utxos, 411384474481955) before retrying.",
      ),
      fee: 411384474481955n,
    },
    {
      name: "the same refusal thrown as a string",
      thrown: "Insufficient generated dust to cover registration fee (have 1, need 2).",
      fee: 2n,
    },
    {
      name: "a node rejection",
      thrown: new Error("1010: Invalid Transaction: Custom error: 170"),
      fee: undefined,
    },
    { name: "something that is not an error", thrown: 42, fee: undefined },
  ];

  it.each(CASES)("reads $name", ({ thrown, fee }) => {
    expect(requiredGeneratedDust(thrown)).toBe(fee);
  });
});
