# Sample Token Whitepaper

## Token economics

The SMP token has a total supply of 1,000,000,000 tokens with 18 decimals.
The max supply is fixed at 1 billion SMP; no further tokens can be created.

## Fees

A transfer tax of 2% applies to every sale, and a protocol fee of 30 bps is charged on swaps.
Liquidity providers earn a commission of 0.25% per trade.

## Governance and administration

Ownership of the token contract has been renounced. The treasury is controlled by a 3-of-5 multisig
with a 48 hour timelock. The staking contract is upgradeable through a UUPS proxy. The token itself
is immutable and has no mint function after launch, but the staking contract is pausable.

## Security

The contracts were audited by Hacken and PeckShield. The audit report is published on the website.

## Deployment

SMP is deployed on Ethereum (0xc2edad668740f1aa35e4d8f227fb8e17dca888cd) and on BNB Chain, with
a Solana wrapper at 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU.
