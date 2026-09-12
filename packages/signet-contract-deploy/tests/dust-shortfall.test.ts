// The facade refusals a fee-paying call can hit for lack of DUST, parsed for
// the amounts they name. Pure: no facade.

import { describe, expect, it } from "vitest";

import { type DustShortfall, dustShortfall } from "../src/index.ts";

describe("dustShortfall", () => {
  /** One thing a facade call may throw, and the shortfall read from it. */
  interface ThrownCase {
    readonly name: string;
    readonly thrown: unknown;
    readonly shortfall: DustShortfall | undefined;
  }

  const CASES: readonly ThrownCase[] = [
    {
      // The facade's verbatim refusal for a 2 NIGHT UTXO registered a minute after landing.
      name: "the facade's insufficient-generated-dust registration refusal",
      thrown: new Error(
        "Insufficient generated dust to cover registration fee (have 396816000000000, need 411384474481955). " +
          "Use WalletFacade.waitForGeneratedDust(utxos, 411384474481955) before retrying.",
      ),
      shortfall: { have: 396816000000000n, need: 411384474481955n },
    },
    {
      name: "the same refusal thrown as a string",
      thrown: "Insufficient generated dust to cover registration fee (have 1, need 2).",
      shortfall: { have: 1n, need: 2n },
    },
    {
      // The wallet sdk balancer's verbatim refusal: it names no amount.
      name: "the balancing refusal",
      thrown: new Error("Insufficient Funds: could not balance dust"),
      shortfall: undefined,
    },
    {
      name: "a node rejection",
      thrown: new Error("1010: Invalid Transaction: Custom error: 170"),
      shortfall: undefined,
    },
    { name: "something that is not an error", thrown: 42, shortfall: undefined },
  ];

  it.each(CASES)("reads $name", ({ thrown, shortfall }) => {
    expect(dustShortfall(thrown)).toEqual(shortfall);
  });
});
