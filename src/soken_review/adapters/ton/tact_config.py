"""tact.config.json allowlist, from the pinned Tact 1.6.13 schema (dist/config/config.zod.js).

Every key and value type the 1.6.13 schema documents is accepted and passed to the compiler,
because each one is visible in the reviewed config and the deployed code depends on it: a rebuild
without them would not reproduce the deployment. Anything else (an unknown key, a wrong type, a
mode outside the schema) is a reason: the candidate is untrusted (tier A blocked) and build.py
then passes only name and path.

Schema (1.6.13): top level `$schema?: string`, `projects: Project[]`; Project `name`, `path`,
`output` (strings), `options?`, `mode?` ("fullWithDecompilation" | "full" | "funcOnly" |
"checkOnly"), `verbose?: number`; options `debug`, `external`, `ipfsAbiGetter`,
`interfacesGetter`, `enableLazyDeploymentCompletedGetter` (bool), `experimental.inline`,
`safety.nullChecks`, `optimizations.alwaysSaveContractData`,
`optimizations.internalExternalReceiversOutsideMethodsMap` (bool).
"""

from __future__ import annotations

from typing import Any

TACT_SCHEMA_VERSION = "1.6.13"

_TOP_KEYS = frozenset({"$schema", "projects"})
_PROJECT_KEYS = frozenset({"name", "path", "output", "options", "mode", "verbose"})
_MODES = frozenset({"fullWithDecompilation", "full", "funcOnly", "checkOnly"})
_BOOL_OPTIONS = frozenset({"debug", "external", "ipfsAbiGetter", "interfacesGetter",
                           "enableLazyDeploymentCompletedGetter"})
_NESTED_OPTIONS: dict[str, frozenset[str]] = {
    "experimental": frozenset({"inline"}),
    "safety": frozenset({"nullChecks"}),
    "optimizations": frozenset({"alwaysSaveContractData", "internalExternalReceiversOutsideMethodsMap"}),
}


def _options(opts: Any, where: str, reasons: list[str]) -> dict[str, Any]:
    if opts is None:
        return {}
    if not isinstance(opts, dict):
        reasons.append(f"{where}: options is not an object")
        return {}
    out: dict[str, Any] = {}
    for key, value in opts.items():
        if key in _BOOL_OPTIONS:
            if not isinstance(value, bool):
                reasons.append(f"{where}: option {key} is not a boolean")
                continue
            out[key] = value
        elif key in _NESTED_OPTIONS:
            if not isinstance(value, dict):
                reasons.append(f"{where}: option {key} is not an object")
                continue
            sub: dict[str, bool] = {}
            for k, v in value.items():
                if k not in _NESTED_OPTIONS[key]:
                    reasons.append(f"{where}: option {key}.{k} is not in the Tact {TACT_SCHEMA_VERSION} schema")
                elif not isinstance(v, bool):
                    reasons.append(f"{where}: option {key}.{k} is not a boolean")
                else:
                    sub[k] = v
            out[key] = sub
        else:
            reasons.append(f"{where}: option {key!r} is not in the Tact {TACT_SCHEMA_VERSION} schema")
    return out


def check_config(cfg: Any, where: str = "tact.config.json") -> tuple[list[dict[str, Any]], list[str]]:
    """(projects as passed to the compiler: name, path, options, mode; reasons). `path` is as given."""
    reasons: list[str] = []
    if not isinstance(cfg, dict) or not isinstance(cfg.get("projects"), list):
        return [], [f"{where}: config without a projects list"]
    extra = set(cfg) - _TOP_KEYS
    if extra:
        reasons.append(f"{where}: config keys {sorted(extra)} are not in the Tact {TACT_SCHEMA_VERSION} schema")
    if "$schema" in cfg and not isinstance(cfg["$schema"], str):
        reasons.append(f"{where}: $schema is not a string")
    projects: list[dict[str, Any]] = []
    for i, proj in enumerate(cfg["projects"]):
        if not isinstance(proj, dict):
            reasons.append(f"{where}: project {i} is not an object")
            continue
        extra = set(proj) - _PROJECT_KEYS
        if extra:
            reasons.append(f"{where}: project keys {sorted(extra)} are not in the Tact {TACT_SCHEMA_VERSION} schema")
        for key in ("name", "path", "output"):
            if key in proj and not isinstance(proj[key], str):
                reasons.append(f"{where}: project {key} is not a string")
        if "verbose" in proj and (isinstance(proj["verbose"], bool) or not isinstance(proj["verbose"], int | float)):
            reasons.append(f"{where}: project verbose is not a number")
        p: dict[str, Any] = {"name": proj.get("name"), "path": proj.get("path"),
                             "options": _options(proj.get("options"), where, reasons)}
        if "mode" in proj:
            if proj["mode"] not in _MODES:
                reasons.append(f"{where}: mode {str(proj['mode'])[:40]!r} is not in the Tact {TACT_SCHEMA_VERSION} schema")
            else:
                p["mode"] = proj["mode"]
        projects.append(p)
    return projects, reasons
