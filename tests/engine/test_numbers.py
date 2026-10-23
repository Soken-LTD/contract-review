"""Unit tests for the number lexer (04 §6). One pass and one fail per rule class.

Plan: 04 §6.1 (scope), §6.2 (lexer L0-L9b), §6.3 (allowed set), §6.4 (placeholders).
"""
from __future__ import annotations

from soken_review.engine.numbers import (
    NumberContext,
    lex_numbers,
    parse_placeholder,
)

# ── helpers ────────────────────────────────────────────────────────────────


def rule_ids(text: str, **ctx_kwargs) -> set[str]:
    ctx = NumberContext(**ctx_kwargs)
    return {v.rule_id for v in lex_numbers(text, ctx)}


def error_codes(text: str, **ctx_kwargs) -> set[str]:
    ctx = NumberContext(**ctx_kwargs)
    return {v.code for v in lex_numbers(text, ctx)}


def passes(text: str, **ctx_kwargs) -> bool:
    ctx = NumberContext(**ctx_kwargs)
    return not lex_numbers(text, ctx)


# ── Step U: non-ASCII numerals ─────────────────────────────────────────────

class TestStepU:
    def test_ascii_digits_pass(self):
        # ASCII digits do not trigger step U (non-ASCII numeral rule)
        assert "U" not in rule_ids("count is 42")

    def test_arabic_indic_digit_rejected(self):
        # U+0661 ARABIC-INDIC DIGIT ONE
        assert "U" in rule_ids("١ item")

    def test_superscript_two_no_rejected(self):
        # U+00B2 is No (superscript 2) -> E_NUMBER_FORMAT from step U
        assert "U" in rule_ids("value²")

    def test_subscript_digit_rejected(self):
        # U+2082 is No (subscript 2)
        assert "U" in rule_ids("10₂")

    def test_fullwidth_digit_rejected(self):
        # U+FF12 is Nd but outside 0-9 -> step U
        assert "U" in rule_ids("value ２０")


# ── L0: placeholders ─────────────────────────────────────────────────────

class TestL0Placeholders:
    def test_fact_placeholder_passes(self):
        assert passes("{{fact:nsloc}}")

    def test_calc_placeholder_passes(self):
        assert passes("{{calc:bps_to_pct(1000)|2}}")

    def test_finding_placeholder_passes(self):
        assert passes("{{finding:my-draft-key}}")

    def test_malformed_placeholder_rejected(self):
        # Not a valid placeholder syntax
        vs = lex_numbers("{{bad:key with spaces}}")
        assert vs  # should produce some violation


# ── L1: code spans ────────────────────────────────────────────────────────

class TestL1CodeSpans:
    def test_number_in_code_span_passes(self):
        # Numbers inside code spans are re-lexed but we accept them in spans
        assert passes("`1000`")

    def test_cardinal_in_code_span_passes(self):
        assert passes("`three`")


# ── L2: hex literals ─────────────────────────────────────────────────────

class TestL2Hex:
    def test_short_hex_passes(self):
        assert passes("0xff")

    def test_hex_in_allowed_set_passes(self):
        ctx = NumberContext(allowed_literals=frozenset(["255"]))
        assert not lex_numbers("0xff", ctx)

    def test_40char_hex_address_passes(self):
        addr = "0x" + "a" * 40
        assert passes(addr)


# ── L3: standard ids ─────────────────────────────────────────────────────

class TestL3StandardIds:
    def test_erc20_passes(self):
        assert passes("ERC-20 token")

    def test_eip1559_passes(self):
        assert passes("EIP-1559 fee")

    def test_swc107_passes(self):
        assert passes("SWC-107")

    def test_cve_2021_passes(self):
        assert passes("CVE-2021-42574")

    def test_cwe_passes(self):
        assert passes("CWE-400")

    def test_bep20_passes(self):
        assert passes("BEP-20")


# ── L4: versions ─────────────────────────────────────────────────────────

class TestL4Versions:
    def test_semver_passes(self):
        assert passes("solc 0.8.20")

    def test_version_with_facts_passes(self):
        ctx = NumberContext(facts={"compiler_version": "0.8.20"})
        assert not lex_numbers("version 0.8.20", ctx)


# ── L7: word with digit ───────────────────────────────────────────────────

class TestL7WordWithDigit:
    def test_type_name_uint256_passes(self):
        assert passes("uint256 value")

    def test_type_name_bytes32_passes(self):
        assert passes("bytes32 hash")

    def test_type_name_u64_passes(self):
        assert passes("u64 timestamp")

    def test_type_name_felt252_passes(self):
        assert passes("felt252 element")

    def test_word_in_word_set_passes(self):
        ctx = NumberContext(word_set=frozenset(["token1"]))
        assert not lex_numbers("token1", ctx)

    def test_unknown_word_with_digit_rejected(self):
        # "reward3x" is not in type_names or word_set
        assert "E_NUMBER_UNSOURCED" in error_codes("reward3x")

    def test_erc20_as_identifier_passes(self):
        # "ERC20" matches L3 (standard id) before L7
        assert passes("ERC20 token")


# ── L8: numeric run (allowed set) ─────────────────────────────────────────

class TestL8NumericRun:
    def test_zero_passes_everywhere(self):
        assert passes("count is 0")

    def test_one_passes_everywhere(self):
        assert passes("one item")

    def test_literal_in_allowed_set_passes(self):
        ctx = NumberContext(allowed_literals=frozenset(["1000"]))
        assert not lex_numbers("1000 units", ctx)

    def test_group_separator_normalization(self):
        # 1,000 == 1000 == 1_000
        ctx = NumberContext(allowed_literals=frozenset(["1000"]))
        assert not lex_numbers("1,000 units", ctx)
        assert not lex_numbers("1_000 units", ctx)

    def test_unsourced_number_rejected(self):
        assert "E_NUMBER_UNSOURCED" in error_codes("the value is 999")

    def test_solidity_unit_value_passes_with_flag(self):
        # 10^18 = 1000000000000000000 (ether)
        ctx = NumberContext(allowed_literals=frozenset(["1000000000000000000"]), include_solidity_units=True)
        assert not lex_numbers("1000000000000000000 wei", ctx)


# ── L8a: currency symbol ──────────────────────────────────────────────────

class TestL8aCurrency:
    def test_dollar_amount_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("$100 tokens")

    def test_euro_amount_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("€50 fee")

    def test_usd_ticker_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("USD 100")

    def test_plain_number_passes(self):
        ctx = NumberContext(allowed_literals=frozenset(["100"]))
        assert not lex_numbers("100", ctx)


# ── L8b: bare percent ────────────────────────────────────────────────────

class TestL8bBarePercent:
    def test_bare_percent_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("fee is 5%")

    def test_percent_via_calc_placeholder_passes(self):
        assert passes("fee is {{calc:bps_to_pct(500)|2}}%")


# ── L8d: magnitude suffix / ordinal ───────────────────────────────────────

class TestL8dMagnitudeSuffix:
    def test_k_suffix_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("5k tokens")

    def test_m_suffix_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("10M supply")

    def test_ordinal_3rd_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("the 3rd call")

    def test_ordinal_1st_passes(self):
        # "1st" – the literal 1 is exempt but "1st" as a whole is E_NUMBER_FORMAT
        # Actually "1" is exempt but "1st" matches L8d -> E_NUMBER_FORMAT
        # The spec says \b\d+(st|nd|rd|th)\b -> E_NUMBER_FORMAT
        assert "E_NUMBER_FORMAT" in error_codes("the 1st call")


# ── L9: cardinal/ordinal words ────────────────────────────────────────────

class TestL9CardinalOrdinal:
    def test_eleven_rejected(self):
        # Above ten a count in words is not a plain number word (L9c) and needs a source
        assert "E_NUMBER_UNSOURCED" in error_codes("eleven iterations are needed")

    def test_twenty_rejected(self):
        assert "E_NUMBER_UNSOURCED" in error_codes("twenty callers can drain")

    def test_fourth_rejected(self):
        assert "E_NUMBER_UNSOURCED" in error_codes("the fourth call")

    def test_third_party_passes(self):
        # Exception: "third party" and "third-party"
        assert passes("a third party contract")
        assert passes("third-party dependency")

    def test_first_passes(self):
        # "first" is exempt_everywhere
        assert passes("the first call")

    def test_second_passes(self):
        assert passes("the second argument")

    def test_last_passes(self):
        assert passes("the last item")


# ── L9c: plain number words (2026-10-23) ─────────────────────────────────

class TestL9cPlainNumberWords:
    """A small count of code things in words needs no source; an amount still does."""

    def test_masterchef_title_passes(self):
        # Rewritten to "An empty totalAllocPoint" in the 2026-10-23 re-run to dodge the gate
        assert passes("A zero totalAllocPoint makes updatePool revert on division")

    def test_small_counts_of_code_things_pass(self):
        assert passes("two callers can drain the pool")
        assert passes("reached from two external governance entry points")
        assert passes("the third call reverts")
        assert passes("a two-step ownership transfer")
        assert passes("two or three pools share one LP token")
        assert passes("Adding the same LP token to two pools divides the rewards")
        assert passes("ten iterations are needed")

    def test_frequency_words_pass(self):
        assert passes("the reward is paid twice")
        assert passes("pending rewards are collected twice during the LP pull")
        assert passes("updatePool runs once per block")

    def test_thrice_still_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("the fee is charged thrice")

    def test_token_word_after_count_rejected(self):
        assert "E_NUMBER_UNSOURCED" in error_codes("two tokens are minted")
        assert "E_NUMBER_UNSOURCED" in error_codes("the attacker receives three ETH")
        assert "E_NUMBER_UNSOURCED" in error_codes("five shares per deposit")

    def test_unit_after_count_rejected(self):
        assert "E_NUMBER_UNSOURCED" in error_codes("the lock lasts five days")
        assert "E_NUMBER_UNSOURCED" in error_codes("a delay of two blocks")
        assert "E_NUMBER_UNSOURCED" in error_codes("a fee of three basis points")

    def test_percent_after_count_rejected(self):
        assert "E_NUMBER_UNSOURCED" in error_codes("a fee of ten percent")
        assert "E_NUMBER_UNSOURCED" in error_codes("ten % of the supply")

    def test_multiplier_after_count_rejected(self):
        assert "E_NUMBER_UNSOURCED" in error_codes("three times the fee")
        assert "E_NUMBER_UNSOURCED" in error_codes("a two-fold increase")
        codes = error_codes("two hundred tokens")
        assert "E_NUMBER_UNSOURCED" in codes and "E_NUMBER_FORMAT" in codes

    def test_fraction_phrase_still_rejected(self):
        # L9b runs before L9c
        assert "E_NUMBER_FORMAT" in error_codes("two thirds of the balance")

    def test_zero_fee_with_bare_percent_still_rejected(self):
        # zero is exempt; the quantity "3 percent" is the unsourced part
        assert "E_NUMBER_UNSOURCED" in error_codes("zero fee of 3 percent")

    def test_code_word_tuple_passes(self):
        # \w{2,}uple: "tuple" is not a multiplier ("Magnitude suffix in tuple", c6 re-run)
        assert passes("the tuple returned by the swap call")

    def test_quadruple_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("a quadruple payout")


# ── L9a: magnitude words ──────────────────────────────────────────────────

class TestL9aMagnitudeWords:
    def test_thousands_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("thousands of tokens")

    def test_double_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("the fee is double the limit")

    def test_half_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("half the supply is burned")

    def test_hundredfold_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("hundredfold increase")


# ── L9b: fraction phrases ────────────────────────────────────────────────

class TestL9bFractionPhrases:
    def test_a_fifth_of_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("a fifth of the supply")

    def test_thirds_of_rejected(self):
        assert "E_NUMBER_FORMAT" in error_codes("thirds of the balance")


# ── Placeholders: parse_placeholder ──────────────────────────────────────

class TestParsePlaceholder:
    def test_fact_placeholder(self):
        ph = parse_placeholder("{{fact:nsloc}}")
        assert ph is not None
        assert ph.kind == "fact"
        assert ph.body == "nsloc"

    def test_fact_with_dots(self):
        ph = parse_placeholder("{{fact:chain.id}}")
        assert ph is not None
        assert ph.kind == "fact"
        assert ph.body == "chain.id"

    def test_finding_placeholder(self):
        ph = parse_placeholder("{{finding:my-draft}}")
        assert ph is not None
        assert ph.kind == "finding"
        assert ph.body == "my-draft"

    def test_calc_bps_to_pct(self):
        ph = parse_placeholder("{{calc:bps_to_pct(1000)|2}}")
        assert ph is not None
        assert ph.kind == "calc"
        assert "bps_to_pct" in ph.body

    def test_calc_with_fact_operand(self):
        ph = parse_placeholder("{{calc:fact:max_bps*fact:fee_bps|4}}")
        assert ph is not None
        assert ph.kind == "calc"

    def test_invalid_returns_none(self):
        assert parse_placeholder("{{invalid}}") is None
        assert parse_placeholder("not a placeholder") is None
        assert parse_placeholder("{{fact:}}") is None  # empty key

    def test_finding_short_key_invalid(self):
        # Draft key must be [a-z0-9][a-z0-9-]{2,47}$ - minimum 3 chars total
        result = parse_placeholder("{{finding:ab}}")
        # "ab" has 2 chars: matches [a-z0-9][a-z0-9-]{2,47} needs at least 3 total -> None
        # Actually the regex is [a-z0-9][a-z0-9-]{2,47} = 1 + 2..47 = 3..48 chars total
        assert result is None or (result.kind == "finding" and len(result.body) >= 3)


# ── Calc rounding ─────────────────────────────────────────────────────────

class TestCalcRounding:
    def test_calc_valid_result_passes(self):
        # bps_to_pct(1000) = 10%, non-zero after rounding
        assert passes("{{calc:bps_to_pct(1000)|2}}")

    def test_calc_very_small_value_rounding(self):
        # bps_to_pct(1) = 0.01% with |2 precision -> 0.01, non-zero
        assert passes("{{calc:bps_to_pct(1)|2}}")

    def test_calc_rounds_to_zero_rejected(self):
        # bps_to_pct(1) with |0 -> 0.01 rounds to 0 -> E_CALC_ROUNDING
        vs = lex_numbers("{{calc:bps_to_pct(1)|0}}")
        calc_vs = [v for v in vs if v.code == "E_CALC_ROUNDING"]
        assert calc_vs, "expected E_CALC_ROUNDING for result rounding to 0"


# ── Line reference (L5) ───────────────────────────────────────────────────

class TestL5LineRef:
    def test_line_in_quote_range_passes(self):
        ctx = NumberContext(
            quoted_line_ranges=[("src/Vault.sol", 10, 20)],
            is_finding=True,
        )
        assert not lex_numbers("src/Vault.sol:15", ctx)

    def test_line_outside_quote_range_rejected(self):
        assert "E_LINEREF_OUTSIDE" in error_codes(
            "src/Vault.sol:50",
            is_finding=True,
            quoted_line_ranges=[("src/Vault.sol", 10, 20)],
        )


# ── Finding reference (L0 finding placeholder) ────────────────────────────

class TestFindingRef:
    def test_known_draft_key_passes(self):
        ctx = NumberContext(draft_keys=frozenset(["my-finding"]))
        assert not lex_numbers("{{finding:my-finding}}", ctx)

    def test_unknown_draft_key_rejected(self):
        ctx = NumberContext(draft_keys=frozenset(["other-finding"]))
        vs = lex_numbers("{{finding:my-finding}}", ctx)
        assert any(v.code == "E_FINDING_REF_UNKNOWN" for v in vs)


class TestFailClosed:
    """Regressions: unevaluable calc and unchecked line references were accepted."""

    def test_calc_unknown_fact_rejected(self):
        from soken_review.engine.numbers import NumberContext, lex_numbers

        codes = [v.code for v in lex_numbers("Fee {{calc:fact:nope*2|0}} units.", NumberContext())]
        assert "E_CALC_SYNTAX" in codes

    def test_calc_division_by_zero_rejected(self):
        from soken_review.engine.numbers import NumberContext, lex_numbers

        codes = [v.code for v in lex_numbers("Ratio {{calc:5/0|2}} here.", NumberContext())]
        assert "E_CALC_SYNTAX" in codes

    def test_lines_outside_quotes_rejected(self):
        from soken_review.engine.numbers import NumberContext, lex_numbers

        ctx = NumberContext(quoted_line_ranges=[("src/A.sol", 10, 20)])
        assert any(v.code == "E_LINEREF_OUTSIDE" for v in lex_numbers("See lines 12 and 90.", ctx))
        assert not any(v.code == "E_LINEREF_OUTSIDE" for v in lex_numbers("See lines 12 and 15.", ctx))
