// Adapts the WalletFacade-based account to midnight-js's wallet interfaces,
// so midnight-js (`findDeployedContract` → `contract.callTx.<circuit>(...)`)
// can balance, prove and submit contract-call transactions through the same
// wallet this package builds. compact-js binds contracts and runs circuits
// locally but does NOT assemble + prove + submit a ledger call transaction —
// midnight-js is the orchestration layer for that. The contract-specific
// provider set (indexer / proof server / zk-config / private-state store)
// lives with each contract package, since it depends on that package's
// compiled assets.

import {
  type MidnightProvider,
  type ProofProvider,
  type UnboundTransaction,
  type WalletProvider,
  type ZKConfigProvider,
  ZKConfigRegistry,
} from "@midnight-ntwrk/midnight-js/types";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import type { WalletFacade } from "@midnightntwrk/wallet-sdk-facade";
import type { AccountKeys } from "@sig-net/midnight-contract-deploy";

// Balancing recipes expire 30 min out (same TTL as submitUnprovenTransaction).
const BALANCE_TTL_MS = 30 * 60 * 1000;

/**
 * Adapt a started {@link WalletFacade} + {@link AccountKeys} to midnight-js's
 * `WalletProvider & MidnightProvider`. `balanceTx` balances the unbound
 * transaction with the account's shielded/dust keys, signs, then finalizes
 * (which proves); `submitTx` relays through the facade.
 *
 * @param facade - A started (and synced) wallet facade.
 * @param keys - The key material of the same wallet, for balancing and signing.
 * @returns The provider pair midnight-js uses as balancer + submitter.
 */
export function createWalletAndMidnightProvider(
  facade: WalletFacade,
  keys: AccountKeys,
): WalletProvider & MidnightProvider {
  return {
    getCoinPublicKey: () => keys.shieldedSecretKeys.coinPublicKey,
    getEncryptionPublicKey: () => keys.shieldedSecretKeys.encryptionPublicKey,
    async balanceTx(tx: UnboundTransaction, ttl?: Date) {
      const recipe = await facade.balanceUnboundTransaction(
        tx,
        { shieldedSecretKeys: keys.shieldedSecretKeys, dustSecretKey: keys.dustSecretKey },
        { ttl: ttl ?? new Date(Date.now() + BALANCE_TTL_MS) },
      );
      const signed = await facade.signRecipe(recipe, keys.unshieldedKeystore.signDataAsync);
      return await facade.finalizeRecipe(signed);
    },
    submitTx: (tx) => facade.submitTransaction(tx),
  };
}

/**
 * Build the {@link ProofProvider} for a contract's provider set: proving via
 * the proof server's /check + /prove endpoints, with proving/verifier keys
 * resolved across a *set* of compiled-contract sources, which is what a
 * **cross-contract call** needs: one transaction whose call tree spans
 * several deployed contracts, each carrying its own proof, so proving must
 * find artifacts for every contract in the tree (the root and each callee).
 * A single-contract call is the one-element case: pass just that contract's
 * provider.
 *
 * The `ZKConfigRegistry` joins each call's canonical key location
 * (`contract:<addr>/<circuitId>?vk=<sha-256 of the deployed verifier key>`) to
 * the source whose local verifier key matches, immune to redeploys and to
 * circuit-name collisions across contracts. Pass one `ZKConfigProvider` per
 * compiled contract the call can reach (the caller plus every callee).
 *
 * @param proofServerUrl - The proof server's HTTP endpoint.
 * @param zkConfigProviders - One provider per compiled contract in the call tree; must be non-empty.
 * @returns The proof provider to place in a contract's midnight-js provider set.
 * @throws {Error} If `zkConfigProviders` is empty.
 */
export function createCrossContractProofServerProvider(
  proofServerUrl: string,
  zkConfigProviders: readonly ZKConfigProvider<string>[],
): ProofProvider {
  if (zkConfigProviders.length === 0) {
    throw new Error(
      "createCrossContractProofServerProvider: at least one zkConfigProvider is required",
    );
  }
  return httpClientProofProvider({
    url: proofServerUrl,
    zkConfigProvider: new ZKConfigRegistry([...zkConfigProviders]),
  });
}
