SushiSwap MasterChef, Ethereum mainnet 0xc2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd, Sourcify match,
solc 0.6.12. The source is the raw Sourcify text (CRLF) that the build step compiles; the pin stores
its LF-normalised twin. `solc_output.sources.json.gz` is the compiler output (`sources` only, AST).
Regression for the semantic-layer line drift on CRLF sources (2026-10-22).
