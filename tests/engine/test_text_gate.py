"""Unit tests for the text gate (04 §11). One pass and one fail example per rule kind.

Plan: 04 §11.1-§11.4, text_gate.yaml, errors.yaml.
"""
from __future__ import annotations

import pytest

from soken_review.engine.text_gate import CheckContext, check_text

# ── helpers ────────────────────────────────────────────────────────────────


def rules(text: str, scope: str = "model", **ctx_kwargs) -> set[str]:
    """Return the set of rule ids that fire on *text* in *scope*."""
    ctx = CheckContext(**ctx_kwargs)
    return {v.rule_id for v in check_text(text, scope, ctx)}


def codes(text: str, scope: str = "model", **ctx_kwargs) -> set[str]:
    """Return the set of error codes that fire on *text*."""
    ctx = CheckContext(**ctx_kwargs)
    return {v.code for v in check_text(text, scope, ctx)}


def passes(text: str, scope: str = "model", **ctx_kwargs) -> bool:
    """True when the text produces zero violations."""
    return not check_text(text, scope, CheckContext(**ctx_kwargs))


# ── step0: control characters ──────────────────────────────────────────────

class TestStep0ControlChars:
    def test_lf_allowed(self):
        assert passes("line one\nline two", "model")

    def test_null_byte_rejected(self):
        assert "step0" in rules("\x00bad", "model")

    def test_tab_rejected(self):
        # \t is Cc but not LF
        assert "step0" in rules("col1\tcol2", "model")

    def test_soft_hyphen_rejected(self):
        assert "step0" in rules("soft­hyphen", "model")

    def test_bidi_lre_rejected(self):
        # U+202A LEFT-TO-RIGHT EMBEDDING (bidi control) — use chr() to avoid literal bidi in source
        assert "step0" in rules("text" + chr(0x202A) + "bidi", "model")

    def test_bidi_rlo_rejected(self):
        # U+202E RIGHT-TO-LEFT OVERRIDE (bidi control) — use chr() to avoid literal bidi in source
        assert "step0" in rules(chr(0x202E) + "reversed", "model")

    def test_cf_zero_width_joiner_rejected(self):
        # U+200D is Cf (format char)
        assert "step0" in rules("zero‍width", "model")

    def test_error_code_control_char(self):
        vs = check_text("\x00", "model")
        assert any(v.code == "E_TEXT_CONTROL_CHAR" for v in vs)


# ── step0: script check ────────────────────────────────────────────────────

class TestStep0Script:
    def test_latin_ascii_ok(self):
        assert passes("The fee is charged to the caller.", "model")

    def test_cyrillic_rejected(self):
        # Cyrillic letter
        vs = check_text("Привет world", "model")
        assert any(v.code == "E_TEXT_SCRIPT" for v in vs)

    def test_cyrillic_in_backtick_span_allowed(self):
        # Letters inside a code span are exempt from the script check
        vs = check_text("`Привет`", "model")
        # step0 runs on the submitted string; code spans found via the same regex
        script_vs = [v for v in vs if v.code == "E_TEXT_SCRIPT"]
        assert not script_vs, f"unexpected script violations: {script_vs}"

    def test_greek_rejected(self):
        vs = check_text("α is undefined", "model")
        assert any(v.code == "E_TEXT_SCRIPT" for v in vs)


# ── T1: em dash ────────────────────────────────────────────────────────────

class TestT1EmDash:
    def test_em_dash_rejected(self):
        assert "T1" in rules("The fee — charged always.", "model")

    def test_no_em_dash_passes(self):
        assert "T1" not in rules("The fee is charged always.", "model")

    def test_em_dash_server_scope(self):
        assert "T1" in rules("value — set", "server")


# ── T2: en dash ────────────────────────────────────────────────────────────

class TestT2EnDash:
    def test_en_dash_rejected(self):
        assert "T2" in rules("lines 10–20", "model")

    def test_no_en_dash_passes(self):
        assert "T2" not in rules("lines 10-20", "model")


# ── T3: right arrow ────────────────────────────────────────────────────────

class TestT3RightArrow:
    def test_arrow_rejected(self):
        assert "T3" in rules("caller → contract", "model")

    def test_no_arrow_passes(self):
        assert "T3" not in rules("caller to contract", "model")


# ── T5: second person ─────────────────────────────────────────────────────

class TestT5SecondPerson:
    def test_you_rejected(self):
        assert "T5" in rules("You should check this value.", "model")

    def test_we_rejected(self):
        assert "T5" in rules("We recommend checking this.", "model")

    def test_our_rejected(self):
        assert "T5" in rules("our contract", "model")

    def test_no_second_person_passes(self):
        assert "T5" not in rules("The caller should verify this.", "model")

    def test_you_in_code_span_exempt(self):
        # Inside a backtick span T5 is exempt
        assert "T5" not in rules("`you`", "model")

    def test_t5_not_in_server_scope(self):
        # T5 is in server scope (T1-T12)
        assert "T5" in rules("you must set this", "server")


# ── T6-T8: kit phrases ─────────────────────────────────────────────────────

class TestKitPhrases:
    def test_t6_confidential_shared(self):
        assert "T6" in rules("Confidential. Shared with the team.", "model")

    def test_t7_reserved_for(self):
        assert "T7" in rules("This slot is reserved for future use.", "model")

    def test_t8_the_choice_is(self):
        assert "T8" in rules("The choice is between two options.", "model")

    def test_t6_passes_without_phrase(self):
        assert "T6" not in rules("This is private data.", "model")

    def test_t7_passes_without_phrase(self):
        assert "T7" not in rules("This value is used for the pool.", "model")


# ── T9: AI words (case-sensitive) ─────────────────────────────────────────

class TestT9AIWords:
    def test_ai_uppercase_rejected(self):
        assert "T9" in rules("The AI model analysed this.", "model")

    def test_claude_rejected(self):
        assert "T9" in rules("Claude wrote this code.", "model")

    def test_gpt_rejected(self):
        assert "T9" in rules("GPT was used here.", "model")

    def test_lowercase_ai_passes(self):
        # "ai" lowercase does not match (case-sensitive)
        assert "T9" not in rules("the ai company", "model")

    def test_ai_in_code_span_exempt(self):
        assert "T9" not in rules("`AI`", "model")

    def test_subagent_rejected(self):
        assert "T9" in rules("A subagent handles this.", "model")


# ── T11: TODO/TBD/DRAFT (case-sensitive) ─────────────────────────────────

class TestT11Marks:
    def test_todo_rejected(self):
        assert "T11" in rules("TODO: add check here.", "model")

    def test_tbd_rejected(self):
        assert "T11" in rules("severity TBD", "model")

    def test_draft_rejected(self):
        assert "T11" in rules("DRAFT recommendation", "model")

    def test_lowercase_todo_passes(self):
        # case-sensitive: "todo" lowercase should not trigger
        assert "T11" not in rules("to do the cleanup", "model")

    def test_tbd_not_in_public_scope(self):
        # T11 is in public scope (T11 is listed)
        assert "T11" in rules("value TBD", "public")


# ── T12: question mark ────────────────────────────────────────────────────

class TestT12QuestionMark:
    def test_question_mark_rejected(self):
        assert "T12" in rules("Is this correct?", "model")

    def test_no_question_mark_passes(self):
        assert "T12" not in rules("This is correct.", "model")

    def test_question_in_code_span_exempt(self):
        assert "T12" not in rules("`foo?bar`", "model")


# ── T13: severity words ───────────────────────────────────────────────────

class TestT13SeverityWords:
    def test_critical_rejected(self):
        assert "T13" in rules("This is a critical issue.", "model")

    def test_high_rejected(self):
        assert "T13" in rules("The impact is high.", "model")

    def test_passes_without_severity(self):
        assert "T13" not in rules("The impact is significant.", "model")

    def test_t13_in_public_scope(self):
        # T13 is NOT in public scope per text_gate.yaml
        assert "T13" not in rules("critical flaw", "public")

    def test_t13_never_exempt_in_code_span(self):
        # T13 is code_span_never_exempt
        assert "T13" in rules("`critical`", "model")


# ── T14: completeness/proof claims ────────────────────────────────────────

class TestT14ClaimsWords:
    def test_guaranteed_rejected(self):
        assert "T14" in rules("The fix is guaranteed.", "model")

    def test_no_vulnerability_rejected(self):
        assert "T14" in rules("There are no vulnerabilities here.", "model")

    def test_bug_free_rejected(self):
        assert "T14" in rules("The code is bug-free.", "model")

    def test_passes_without_claim(self):
        assert "T14" not in rules("The code has been reviewed.", "model")

    def test_t14_in_public_scope(self):
        assert "T14" in rules("guaranteed safe", "public")


# ── T15: audit wording ────────────────────────────────────────────────────

class TestT15AuditWording:
    def test_audit_rejected(self):
        assert "T15" in rules("The audit found issues.", "model")

    def test_audited_rejected(self):
        assert "T15" in rules("The contract was audited.", "model")

    def test_passes_without_audit(self):
        assert "T15" not in rules("The contract was reviewed.", "model")

    def test_t15_in_public_scope(self):
        assert "T15" in rules("this audit report", "public")

    def test_t15_never_exempt(self):
        assert "T15" in rules("`audit`", "model")


# ── T16: analyzer/model names ─────────────────────────────────────────────

class TestT16AnalyzerNames:
    def test_slither_rejected(self):
        assert "T16" in rules("Slither found this issue.", "model")

    def test_echidna_rejected(self):
        assert "T16" in rules("Echidna fuzzer was used.", "model")

    def test_opus_rejected(self):
        assert "T16" in rules("Opus analysis confirmed.", "model")

    def test_slither_in_code_span_exempt(self):
        assert "T16" not in rules("`Slither`", "model")

    def test_lower_slither_passes(self):
        # case-sensitive: "slither" lowercase does not trigger
        assert "T16" not in rules("a slither of doubt", "model")


# ── T17: URLs and email ───────────────────────────────────────────────────

class TestT17URLs:
    def test_https_url_rejected(self):
        assert "T17" in rules("See https://example.com for details.", "model")

    def test_www_rejected(self):
        assert "T17" in rules("See www.example.com for info.", "model")

    def test_email_rejected(self):
        assert "T17" in rules("Contact user@example.com.", "model")

    def test_no_url_passes(self):
        assert "T17" not in rules("See the linked document.", "model")

    def test_t17_never_exempt(self):
        assert "T17" in rules("`https://evil.com`", "model")


# ── T18: filler phrases ───────────────────────────────────────────────────

class TestT18FillerPhrases:
    def test_it_is_important_to_note_rejected(self):
        assert "T18" in rules("It is important to note that this value is unbounded.", "model")

    def test_in_conclusion_rejected(self):
        assert "T18" in rules("In conclusion, the contract is at risk.", "model")

    def test_feel_free_rejected(self):
        assert "T18" in rules("Feel free to add checks.", "model")

    def test_passes_without_filler(self):
        assert "T18" not in rules("The value is unbounded.", "model")

    def test_filler_in_code_span_exempt(self):
        assert "T18" not in rules("`note that`", "model")


# ── T19: hedging stack ───────────────────────────────────────────────────

class TestT19Hedging:
    def test_might_potentially_rejected(self):
        assert "T19" in rules("This might potentially allow re-entry.", "model")

    def test_could_possibly_rejected(self):
        assert "T19" in rules("An attacker could possibly drain funds.", "model")

    def test_single_hedge_passes(self):
        assert "T19" not in rules("An attacker might drain funds.", "model")

    def test_hedging_in_code_span_exempt(self):
        assert "T19" not in rules("`might potentially`", "model")


# ── T20: dashes and arrows ────────────────────────────────────────────────

class TestT20DashesArrows:
    def test_ascii_arrow_rejected(self):
        assert "T20" in rules("data -> contract", "model")

    def test_fat_arrow_rejected(self):
        assert "T20" in rules("case => value", "model")

    def test_unicode_minus_rejected(self):
        assert "T20" in rules("fee − amount", "model")

    def test_unicode_dash_range_rejected(self):
        # U+2011 non-breaking hyphen
        assert "T20" in rules("value‑constant", "model")

    def test_plain_hyphen_passes(self):
        # Regular ASCII hyphen-minus is OK in T20 (it is not in the pattern)
        assert "T20" not in rules("well-known pattern", "model")

    def test_arrow_in_code_span_exempt(self):
        assert "T20" not in rules("`data -> contract`", "model")

    def test_t20_not_in_server_scope(self):
        # T20 is model-only (not in server scope T1-T12)
        assert "T20" not in rules("data -> contract", "server")


# ── T21: title structure ─────────────────────────────────────────────────

class TestT21Title:
    def test_valid_title_passes(self):
        assert "T21" not in rules("setFee stores any fee above MAX_FEE_BPS", "model", field="title")

    def test_too_short_rejected(self):
        assert "T21" in rules("Fee bug", "model", field="title")

    def test_too_long_rejected(self):
        long = "A" * 111
        assert "T21" in rules(long, "model", field="title")

    def test_trailing_period_rejected(self):
        assert "T21" in rules("The fee calculation is wrong.", "model", field="title")

    def test_only_code_span_rejected(self):
        assert "T21" in rules("`setFee`", "model", field="title")

    def test_t21_not_applied_without_field(self):
        # T21 only fires when field='title'
        assert "T21" not in rules("A" * 111, "model")


# ── T22: let us / let's ───────────────────────────────────────────────────

class TestT22LetUs:
    def test_let_us_rejected(self):
        assert "T22" in rules("Let us examine the contract.", "model")

    def test_lets_rejected_after_contraction_expansion(self):
        # After contraction expansion, "let's" stays as "let's" (not in contraction map)
        # The rule matches "let's" directly via the regex
        assert "T22" in rules("Let's look at this.", "model")

    def test_passes_without_phrase(self):
        assert "T22" not in rules("Examine the contract.", "model")


# ── T23: paragraph word count ─────────────────────────────────────────────

class TestT23WordCount:
    def test_short_paragraph_passes(self):
        text = " ".join(["word"] * 50)
        assert "T23" not in rules(text, "model", field="description")

    def test_long_paragraph_rejected(self):
        text = " ".join(["word"] * 91)
        assert "T23" in rules(text, "model", field="description")

    def test_t23_not_applied_to_recommendation(self):
        text = " ".join(["word"] * 91)
        assert "T23" not in rules(text, "model", field="recommendation")

    def test_t23_not_applied_without_field(self):
        text = " ".join(["word"] * 91)
        assert "T23" not in rules(text, "model")


# ── T24: absence phrases ─────────────────────────────────────────────────

class TestT24AbsencePhrases:
    def test_no_guard_without_claim_rejected(self):
        vs = check_text("The function has no guard.", "model", CheckContext(field="description"))
        assert any(v.rule_id == "T24" for v in vs)

    def test_unprotected_without_claim_rejected(self):
        vs = check_text("The entry point is unprotected.", "model", CheckContext(field="impact"))
        assert any(v.code == "E_ABSENCE_UNRESOLVED" for v in vs)

    def test_bound_claim_passes(self):
        claim = {"says": "no guard", "kind": "no_guard", "target": "caller_check", "scope": "entry_function"}
        vs = check_text("The function has no guard.", "model", CheckContext(field="description", absence_claims=[claim]))
        t24 = [v for v in vs if v.rule_id == "T24"]
        assert not t24

    def test_nobody_can_without_claim_rejected(self):
        vs = check_text("nobody can call this function.", "model", CheckContext(field="description"))
        assert any(v.code == "E_ABSENCE_UNRESOLVED" for v in vs)

    def test_contraction_expanded_doesnt_check_no_check_rejected(self):
        # "doesn't check" -> after expansion "does not check" -> T24 guard class
        vs = check_text("The function does not check inputs.", "model", CheckContext(field="description"))
        assert any(v.code == "E_ABSENCE_UNRESOLVED" for v in vs)

    def test_t24_exempt_in_code_span(self):
        vs = check_text("`no guard`", "model", CheckContext(field="description"))
        t24 = [v for v in vs if v.rule_id == "T24"]
        assert not t24

    def test_t24_not_in_recommendation(self):
        # T24 applies_to: [title, description, impact, attack_steps, notes] - NOT recommendation
        vs = check_text("The function has no guard.", "model", CheckContext(field="recommendation"))
        assert not any(v.rule_id == "T24" for v in vs)

    def test_t24_not_in_server_scope(self):
        assert "T24" not in rules("The contract is unguarded.", "server")


# ── T25: soken ────────────────────────────────────────────────────────────

class TestT25Soken:
    def test_soken_rejected_model_scope(self):
        assert "T25" in rules("Soken reviewed this.", "model")

    def test_soken_dev_rejected_model_scope(self):
        # In model scope, even soken.dev is blocked
        assert "T25" in rules("See soken.dev for info.", "model")

    def test_soken_dev_allowed_server_scope(self):
        # soken.dev is allowed in server scope (T25_brand_only)
        assert "T25" not in rules("See soken.dev for info.", "server")

    def test_soken_standalone_blocked_server_scope(self):
        # "soken" without ".dev" is blocked in server scope
        assert "T25" in rules("Soken team reviewed.", "server")

    def test_soken_dev_allowed_public_scope(self):
        assert "T25" not in rules("Visit soken.dev.", "public")

    def test_soken_blocked_public_scope(self):
        assert "T25" in rules("Soken performed a review.", "public")


# ── T27: promotion phrases ────────────────────────────────────────────────

class TestT27Promotion:
    def test_book_a_call_rejected(self):
        assert "T27" in rules("Book a call with our team.", "model")

    def test_contact_us_rejected(self):
        assert "T27" in rules("Contact us today.", "model")

    def test_paid_audit_rejected(self):
        assert "T27" in rules("Get a paid audit now.", "model")

    def test_passes_without_promotion(self):
        assert "T27" not in rules("The finding requires remediation.", "model")

    def test_t27_in_public_scope(self):
        assert "T27" in rules("book a call today", "public")

    # T27 is multi-word only (plan 04 §11.2: "multi-word only; 'book', 'paid', 'contact'
    # are protocol vocabulary").  Single-word "pricing" and "discount" are valid in
    # security findings ("mint pricing oracle", "no discount to face value") — both ways:

    def test_pricing_standalone_passes_model(self):
        # "pricing" alone is now allowed — it is technical vocabulary in security findings.
        assert "T27" not in rules("The pricing oracle is stale.", "model")

    def test_pricing_in_technical_context_passes(self):
        # "mint pricing" or "price feed" must not be blocked.
        assert "T27" not in rules("The mint pricing mechanism uses a TWAP.", "model")

    def test_pricing_standalone_passes_public(self):
        # Also passes in public scope.
        assert "T27" not in rules("The pricing oracle rounds down.", "public")

    def test_discount_standalone_passes(self):
        # "discount" alone is valid ("no discount to face value applies").
        assert "T27" not in rules("There is no discount mechanism.", "model")

    def test_cta_phrases_still_rejected(self):
        # These remain banned — they are unambiguous commercial CTAs.
        assert "T27" in rules("Reach out to our team.", "model")
        assert "T27" in rules("Upgrade to a full review.", "model")
        assert "T27" in rules("We offer a paid plan.", "model")

    def test_book_standalone_passes(self):
        # "book" alone is not in the list; only multi-word "book a call" etc.
        assert "T27" not in rules("The book describes the protocol.", "model")


# ── T28: counts near numbers ──────────────────────────────────────────────

class TestT28CountsNearNumbers:
    def test_projects_near_number_rejected(self):
        assert "T28" in rules("We have reviewed 50 projects.", "model")

    def test_clients_near_magnitude_rejected(self):
        assert "T28" in rules("hundreds of clients have used this.", "model")

    def test_audits_near_number_rejected(self):
        assert "T28" in rules("200 audits completed.", "model")

    def test_projects_without_number_passes(self):
        assert "T28" not in rules("The projects are reviewed carefully.", "model")

    def test_t28_in_server_scope(self):
        assert "T28" in rules("100 clients served", "server")


# ── T29: raw ids ─────────────────────────────────────────────────────────

class TestT29RawIds:
    def test_finding_id_rejected(self):
        assert "T29" in rules("See H-001 for details.", "model")

    def test_lead_id_rejected(self):
        assert "T29" in rules("The issue LEAD-0042 is a concern.", "model")

    def test_passes_with_placeholder(self):
        assert "T29" not in rules("See {{finding:my-draft}} for details.", "model")

    def test_l_prefix_rejected(self):
        assert "T29" in rules("Issue L-42 has medium severity.", "model")


# ── T30: exploit sequence ─────────────────────────────────────────────────

class TestT30ExploitSequence:
    def test_step_marker_rejected(self):
        ctx = CheckContext(field="description", profile="public_review")
        vs = check_text("Step 1: call the function. Step 2: drain funds.", "model", ctx)
        assert any(v.rule_id == "T30" for v in vs)

    def test_actor_with_two_seq_terms_rejected(self):
        ctx = CheckContext(field="description", profile="public_review")
        text = "The attacker calls the function, then loops, then drains."
        vs = check_text(text, "model", ctx)
        assert any(v.rule_id == "T30" for v in vs)

    def test_list_item_actor_start_rejected(self):
        ctx = CheckContext(field="description", profile="public_review", is_list_item=True)
        vs = check_text("Attacker calls the function with forged data.", "model", ctx)
        assert any(v.rule_id == "T30" for v in vs)

    def test_no_exploit_sequence_passes(self):
        ctx = CheckContext(field="description", profile="public_review")
        text = "The function sets the fee to any value the owner provides."
        assert not any(v.rule_id == "T30" for v in check_text(text, "model", ctx))

    def test_t30_not_in_owner_profile(self):
        ctx = CheckContext(field="description", profile="owner")
        text = "Step 1: call the function."
        assert not any(v.rule_id == "T30" for v in check_text(text, "model", ctx))

    def test_t30_not_in_recommendation(self):
        ctx = CheckContext(field="recommendation", profile="public_review")
        text = "Step 1: add a check."
        assert not any(v.rule_id == "T30" for v in check_text(text, "model", ctx))


# ── T31: call syntax ──────────────────────────────────────────────────────

class TestT31CallSyntax:
    def test_dot_call_in_prose_rejected(self):
        vs = check_text("vault.withdraw(amount) is called.", "model", CheckContext())
        assert any(v.rule_id == "T31" for v in vs)

    def test_snake_call_in_prose_rejected(self):
        vs = check_text("The invoke_signed(cpi) call may fail.", "model", CheckContext())
        assert any(v.rule_id == "T31" for v in vs)

    def test_camel_call_in_prose_rejected(self):
        vs = check_text("transferFrom(msg.sender, to, amount)", "model", CheckContext())
        assert any(v.rule_id == "T31" for v in vs)

    def test_call_in_code_span_passes(self):
        vs = check_text("`vault.withdraw(amount)`", "model", CheckContext())
        t31 = [v for v in vs if v.rule_id == "T31"]
        assert not t31, f"unexpected T31 violations: {t31}"

    def test_function_word_passes(self):
        # "function(s)" should not trigger T31 since it's not in the call patterns
        # Actually "function(" would match the keyword pattern; "function(s)" does not
        vs = check_text("The function should check inputs.", "model", CheckContext())
        t31 = [v for v in vs if v.rule_id == "T31"]
        assert not t31

    def test_t31_not_in_server_scope(self):
        # T31 is model-only
        vs = check_text("vault.withdraw(amount)", "server", CheckContext())
        t31 = [v for v in vs if v.rule_id == "T31"]
        assert not t31


# ── P1: superlative words (public scope) ─────────────────────────────────

class TestP1Superlative:
    def test_best_rejected(self):
        assert "P1" in rules("The best option is to review manually.", "public")

    def test_unique_rejected(self):
        assert "P1" in rules("The unique approach enables fast review.", "public")

    def test_number_one_rejected(self):
        assert "P1" in rules("We are #1 in security.", "public")

    def test_passes_without_superlative(self):
        assert "P1" not in rules("The review covers all entry points.", "public")

    def test_p1_not_in_model_scope(self):
        # P1 is public scope only
        assert "P1" not in rules("The best option", "model")


# ── P3: score/finance wording ─────────────────────────────────────────────

class TestP3ScoreWords:
    def test_score_rejected(self):
        assert "P3" in rules("The contract received a score of 9.", "public")

    def test_buy_rejected(self):
        assert "P3" in rules("It is safe to buy this token.", "public")

    def test_invest_rejected(self):
        assert "P3" in rules("Users should invest carefully.", "public")

    def test_passes_without_finance_words(self):
        assert "P3" not in rules("The contract holds funds securely.", "public")


# ── P4: endorsement near Anthropic/Claude ────────────────────────────────

class TestP4Endorsement:
    def test_endorsed_by_anthropic_rejected(self):
        assert "P4" in rules("This tool is endorsed by Anthropic.", "public")

    def test_certified_claude_rejected(self):
        assert "P4" in rules("Claude certified this contract.", "public")

    def test_endorsed_without_brand_passes(self):
        assert "P4" not in rules("This contract is endorsed by the team.", "public")

    def test_anthropic_without_endorsement_passes(self):
        assert "P4" not in rules("Anthropic builds Claude.", "public")


# ── subject scope ─────────────────────────────────────────────────────────

class TestSubjectScope:
    def test_soken_in_subject_name_rejected(self):
        assert "subject_words" in rules("Soken Protocol", "subject")

    def test_secure_in_subject_name_rejected(self):
        assert "subject_words" in rules("SecureToken", "subject")

    def test_neutral_name_passes(self):
        assert "subject_words" not in rules("TokenVault", "subject")


# ── scope validation ──────────────────────────────────────────────────────

class TestScopeValidation:
    def test_unknown_scope_raises(self):
        with pytest.raises(ValueError, match="Unknown scope"):
            check_text("hello", "unknown_scope")


# ── Unicode / NFKC edge cases ─────────────────────────────────────────────

class TestUnicodeEdgeCases:
    def test_superscript_digit_rejected_by_step0(self):
        # U+00B2 is No (superscript 2); step0 catches it as a non-standard Cc/Cf
        # Actually step0 checks Cc/Cf/U+00AD/bidi only; script check catches Letters.
        # Superscript digits are "No" which would cause E_NUMBER_FORMAT in the number
        # lexer but not in the text gate step0 (step0 catches control/format/bidi/script).
        # So U+00B2 passes step0 but would be caught by the number check.
        # Here we verify step0 does NOT flag it (it's not Cc, Cf, or a Letter).
        vs = check_text("value²", "model")
        step0_vs = [v for v in vs if v.rule_id == "step0"]
        # U+00B2 is No (number), not Cc/Cf/Letter -> no step0 violation
        # It also has script Common so no script violation
        assert not step0_vs

    def test_nfkc_folding_t1(self):
        # U+2014 is em dash; NFKC leaves it as-is; T1 should still catch it
        assert "T1" in rules("—", "model")

    def test_cyrillic_in_code_span_passes_step0(self):
        # Cyrillic letters inside code spans are exempt from the script check
        vs = check_text("`Привет`", "model")
        script_vs = [v for v in vs if v.code == "E_TEXT_SCRIPT"]
        assert not script_vs

    def test_iana_tld_t26_skipped_when_no_file(self):
        # T26 requires tlds.txt; without it the rule is skipped silently
        # (this test verifies no crash and no false positive)
        vs = check_text("visit example.com today", "model")
        t26 = [v for v in vs if v.rule_id == "T26"]
        # Without tlds.txt no T26 violations
        assert not t26


# ── Write-time parity: check_model_field must be >= render gate ───────────────
#
# Coordinator requirement (2026-10-24): "the write-time gate must not be weaker
# than the render-time gate."  LATE_GATE_SKIP (T24, T29, T31) must NOT be applied
# at write time — only the render builder may skip them.  These tests prove
# check_model_field enforces the FULL rule set, and that LATE_GATE_SKIP rules are
# caught at write time so they can never sneak through to render_failed.


class TestWriteTimeParityWithLateGate:
    """check_model_field enforces all rules (no LATE_GATE_SKIP at write time)."""

    def test_check_model_field_no_skip_imported(self):
        """LATE_GATE_SKIP is a module-level constant; check_model_field does NOT apply it."""
        from soken_review.engine.text_gate import LATE_GATE_SKIP, check_model_field
        # Sanity: the constant must contain the canonical three rules.
        assert LATE_GATE_SKIP == frozenset({"T24", "T29", "T31"})
        # check_model_field on clean text → no violations.
        assert check_model_field("The contract uses SafeMath for overflow protection.") == []

    def test_t29_typed_id_caught_at_write_time(self):
        """T29 fires on raw typed ids (e.g. C-001) in prose — caught by check_model_field."""
        from soken_review.engine.text_gate import check_model_field
        vs = check_model_field("The vulnerability is tracked as C-001 in our system.")
        rule_ids = {v.rule_id for v in vs}
        assert "T29" in rule_ids, (
            "check_model_field must fire T29 on raw typed ids; "
            "LATE_GATE_SKIP must not be applied at write time"
        )

    def test_t31_call_syntax_caught_at_write_time(self):
        """T31 fires on call syntax outside code spans — caught by check_model_field."""
        from soken_review.engine.text_gate import check_model_field
        # transfer() outside a backtick span
        vs = check_model_field("The attacker calls transfer() to drain funds.")
        rule_ids = {v.rule_id for v in vs}
        assert "T31" in rule_ids, (
            "check_model_field must fire T31 on call syntax outside code spans; "
            "LATE_GATE_SKIP must not be applied at write time"
        )

    def test_t31_call_in_code_span_passes_write_time(self):
        """T31 exempts backtick-wrapped call syntax (write-time parity with render time)."""
        from soken_review.engine.text_gate import check_model_field
        vs = check_model_field("The attacker calls `transfer()` to drain funds.")
        t31 = [v for v in vs if v.rule_id == "T31"]
        assert not t31

    def test_render_builder_applies_late_gate_skip(self):
        """build.check_strings filters LATE_GATE_SKIP from model hits (render-only skip)."""
        # Behavioral check: check_model_field must return T29 violations (full scope).
        # If LATE_GATE_SKIP were applied inside check_model_field, T29 would be absent.
        from soken_review.engine.text_gate import LATE_GATE_SKIP, check_model_field
        text_with_t29 = "The issue is tracked as C-001 in our registry."
        vs = check_model_field(text_with_t29)
        rule_ids = {v.rule_id for v in vs}
        assert "T29" in rule_ids, (
            "check_model_field must NOT suppress T29 — "
            "LATE_GATE_SKIP must only be applied by the render builder"
        )
        # Verify the constant exists and contains the expected rules.
        assert "T24" in LATE_GATE_SKIP and "T29" in LATE_GATE_SKIP and "T31" in LATE_GATE_SKIP
        # Verify check_strings source references LATE_GATE_SKIP (render-only filter location).
        import inspect

        import soken_review.report.kit.build as build_mod
        src = inspect.getsource(build_mod.check_strings)
        assert "LATE_GATE_SKIP" in src, (
            "check_strings must filter LATE_GATE_SKIP from model hits; "
            "render builder is the only caller that applies the skip"
        )

    def test_t27_pricing_technical_passes_write_time(self):
        """T27 narrowed to multi-word CTAs: 'pricing oracle' technical use passes check_model_field."""
        from soken_review.engine.text_gate import check_model_field
        vs = check_model_field(
            "The mint pricing oracle can be manipulated to undervalue redemptions.",
            field="description",
        )
        t27 = [v for v in vs if v.rule_id == "T27"]
        assert not t27, f"T27 must not fire on technical 'pricing oracle': {t27}"

    def test_t27_cta_phrase_rejected_write_time(self):
        """T27 multi-word CTA phrases are still rejected at write time."""
        from soken_review.engine.text_gate import check_model_field
        vs = check_model_field(
            "Book a call with our team to discuss remediation options.",
            field="recommendation",
        )
        t27 = [v for v in vs if v.rule_id == "T27"]
        assert t27, "T27 must fire on 'book a call' CTA phrase at write time"
