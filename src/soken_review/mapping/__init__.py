"""Contract map `map.v1` and server facts (04 sections 2.1, 2.2, 6.3; 03 sections 4.6, 4.8).

`lexers` tokenizes one file (grammar parser, else the `lexers.yaml` fallback). `lexical` builds the
lexical layer for a pinned job, `semantic_evm` the semantic layer from the solc AST, `facts` the
fact records, `store` writes and loads the job artifacts. Pure engine checks over these artifacts
live in `engine.artifacts`.
"""
