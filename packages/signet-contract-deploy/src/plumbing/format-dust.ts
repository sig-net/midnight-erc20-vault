/**
 * Format SPECKs as DUST with all 15 decimal places preserved when significant.
 *
 * @param specks - The amount in atomic DUST units.
 * @returns The decimal DUST amount, without a unit suffix.
 */
export function formatDust(specks: bigint): string {
  const magnitude: string = (specks < 0n ? -specks : specks).toString().padStart(16, "0");
  let fraction: string = magnitude.slice(-15);
  while (fraction.endsWith("0")) fraction = fraction.slice(0, -1);
  return `${specks < 0n ? "-" : ""}${magnitude.slice(0, -15)}${fraction ? `.${fraction}` : ""}`;
}
