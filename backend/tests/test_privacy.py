from __future__ import annotations

from cloak.privacy import (
    MAX_CUMULATIVE_EDIT_RATIO,
    MAX_PER_PASS_EDIT_RATIO,
    apply_exact_patch,
    candidate_from_text,
    check_utility,
    deterministic_task_facts,
    english_scope_supported,
    ground_quote,
    identity_rank,
    normalize_input,
    repair_sentence_replacement,
    tokenizable_specifics,
)
from cloak.vault import LocalVault


def test_normalize_input_uses_lf_nfc_and_codepoint_limit() -> None:
    assert normalize_input("Cafe\u0301\r\nline") == "Café\nline"


def test_identity_match_is_exact_after_conservative_normalization() -> None:
    aliases = ["Mara Voss", "M. Voss"]
    assert identity_rank(["  MARA VOSS.  "], aliases) == 1
    assert identity_rank(["Mara Vos"], aliases) is None
    assert identity_rank(["Mara Voss, reporter"], aliases) is None


def test_quote_must_be_unique_and_offsets_include_utf16() -> None:
    text = "😀 clue then context"
    evidence = ground_quote(text, "clue")
    assert evidence.status == "grounded"
    assert evidence.codepoint_start == 2
    assert evidence.utf16_start == 3
    assert ground_quote("same / same", "same").status == "ambiguous"
    assert ground_quote(text, "invented").status == "missing"


def test_vault_uses_consistent_natural_surrogates_and_restores_locally() -> None:
    vault = LocalVault(secret=b"x" * 32)
    original = "Mara Voss emailed mara@example.com. Voss replied."
    sanitized = vault.sanitize(
        original,
        ["Mara Voss", "Voss"],
        ["mara@example.com"],
    )
    handles = vault.handles_in_text(sanitized)
    assert len(handles) == 3
    assert handles[0].split()[-1] == handles[2]
    assert "[[CX_" not in sanitized
    assert "@example.invalid" in sanitized
    assert "Mara Voss" not in sanitized
    assert "mara@example.com" not in sanitized
    restored = vault.restore(sanitized)
    assert restored.restored_count == 3
    assert restored.restored_text == original
    assert not restored.unknown_tokens


def test_vault_surrogates_are_session_unlinkable_and_preserve_identifier_roles() -> None:
    original = (
        "Mara Voss of Meridian Health LLC lives at 41 River Road, Raleigh, NC 27601; "
        "employee EMP-69241, phone (919) 555-0144."
    )
    identifiers = [
        "Meridian Health LLC",
        "41 River Road, Raleigh, NC 27601",
        "EMP-69241",
        "(919) 555-0144",
    ]
    first = LocalVault(secret=b"a" * 32)
    second = LocalVault(secret=b"b" * 32)
    first_text = first.sanitize(original, ["Mara Voss"], identifiers)
    second_text = second.sanitize(original, ["Mara Voss"], identifiers)

    assert first_text != second_text
    assert first.restore(first_text).restored_text == original
    assert second.restore(second_text).restored_text == original
    assert "EMP-" in first_text
    assert "LLC" in first_text
    assert "555" in first_text
    assert all(value not in first_text for value in ["Mara Voss", *identifiers])


def test_vault_tokenizes_case_variants_and_restores_each_original_surface() -> None:
    vault = LocalVault(secret=b"x" * 32)
    original = "Alan Turing reviewed ALAN TURING notes sent to ALAN@EXAMPLE.COM."
    sanitized = vault.sanitize(original, ["Alan Turing"], ["alan@example.com"])
    assert "Alan Turing" not in sanitized
    assert "ALAN TURING" not in sanitized
    assert "ALAN@EXAMPLE.COM" not in sanitized
    assert vault.restore(sanitized).restored_text == original


def test_vault_tokenizes_full_unicode_casefold_expansions() -> None:
    vault = LocalVault(secret=b"x" * 32)
    original = "Straße reviewed STRASSE notes while Maße checked MASSE totals."
    sanitized = vault.sanitize(original, ["Straße"], ["Maße"])
    assert "Straße" not in sanitized
    assert "STRASSE" not in sanitized
    assert "Maße" not in sanitized
    assert "MASSE" not in sanitized
    assert vault.restore(sanitized).restored_text == original


def test_one_character_surrogate_mutations_are_flagged_across_names_and_contacts() -> None:
    vault = LocalVault(secret=b"x" * 32)
    original = "Mara Voss emailed mara@example.com or called (919) 555-0144."
    sanitized = vault.sanitize(
        original,
        ["Mara Voss"],
        ["mara@example.com", "(919) 555-0144"],
    )
    assert len(vault.known_handles) == 3
    for original_handle in vault.known_handles:
        index = next(position for position, character in enumerate(original_handle) if character.isalnum())
        replacement = "x" if original_handle[index].casefold() != "x" else "y"
        altered_handle = f"{original_handle[:index]}{replacement}{original_handle[index + 1:]}"
        result = vault.restore(sanitized.replace(original_handle, altered_handle))
        assert result.mutated_tokens == [altered_handle]
        assert result.unknown_tokens == []
        assert result.missing_tokens == []
        assert result.restored_count == 2


def test_staged_inferred_entity_tokenization_is_exact_and_transactional() -> None:
    vault = LocalVault(secret=b"x" * 32)
    fragment = "14 Jun — Laurent Hotel, Montreal — $612.00"
    staged_text, staged = vault.stage_fragment_tokenization(fragment, ["Laurent", "Montreal"])
    assert "Laurent" not in staged_text
    assert "Hotel" in staged_text
    assert "$612.00" in staged_text
    assert not vault.token_to_value

    vault.commit_staged_tokens(staged, staged_text)
    restored = vault.restore(staged_text)
    assert restored.restored_text == fragment
    assert restored.restored_count == 2


def test_utility_rejects_token_loss_pin_loss_and_large_edits() -> None:
    token = "[[CX_MFRGGZDFMZTWQ2LK_4d2c6a1f]]"  # noqa: S105 - synthetic opaque token
    original = f"{token} wrote a precise report for the city council. Keep this sentence."
    quote = ground_quote(original, "a precise report")
    proposed = "A completely unrelated rewrite with none of the required content."
    ledger = check_utility(
        previous=original,
        proposed=proposed,
        original_sanitized=original,
        pins=["Keep this sentence."],
        expected_tokens=[token],
        authorized_quote=quote,
        replacement="a general report",
    )
    assert not ledger.accepted
    assert not ledger.tokens_intact
    assert not ledger.pins_intact
    assert not ledger.authorized_span_only


def test_task_fact_floor_protects_financial_values_and_hr_direct_statement() -> None:
    financial = deterministic_task_facts(
        "Review fees, utilization, and numerically grounded payment risks.",
        "Credit limit: $8,000.00. Payment due date: 24 July 2026. APR 24.99%.",
    )
    assert "$8,000.00" in financial
    assert "24 July 2026" in financial
    assert "24.99%" in financial
    assert "Credit limit: $8,000.00. Payment due date: 24 July 2026. APR 24.99%." in financial

    statement = "On 12 February, my manager said the role needed someone without a new baby."
    hr = deterministic_task_facts("Build a chronology and separate direct evidence from inference.", statement)
    assert statement in hr


def test_task_fact_floor_is_not_bypassed_by_natural_task_wording() -> None:
    invoice = deterministic_task_facts(
        "Calculate whether the invoice can be paid from the available balance.",
        "Evelyn Brooks approved an invoice for $612.00 on 14 June 2026.",
    )
    assert "$612.00" in invoice
    assert "14 June 2026" in invoice

    medication = deterministic_task_facts(
        "Check whether the dose is safe given the laboratory results.",
        "Leila Haddad takes adalimumab 40 mg every other week.",
    )
    assert "40 mg" in medication
    assert "one week" not in medication

    role_sentence = "[[CX_MFRGGZDFMZTWQ2LK_4d2c6a1f]] served as trustee for the pension plan."
    roles = deterministic_task_facts("Identify each person's exact role and fiduciary obligations.", role_sentence)
    assert role_sentence in roles

    statement = "The manager said the promotion panel needed someone without a new baby."
    quoted = deterministic_task_facts("Quote what the manager said and explain why it matters.", statement)
    assert statement in quoted

    directional = "The board terminated [[CX_MFRGGZDFMZTWQ2LK_4d2c6a1f]] after an audit."
    relation = deterministic_task_facts("Explain who terminated whom and why.", directional)
    assert directional in relation

    promotion = "The manager promoted the employee to lead the project."
    polarity = deterministic_task_facts("Determine whether the manager promoted or demoted the employee.", promotion)
    assert promotion in polarity


def test_english_scope_rejects_clear_non_english_prose_without_rejecting_names() -> None:
    assert english_scope_supported("María López wrote the report and kept the exact chronology for the review.")
    assert not english_scope_supported(
        "María López redactó el informe y mantuvo la cronología exacta para la revisión."
    )
    assert not english_scope_supported("María López redactó informe completo manteniendo cronología exacta necesaria.")
    assert not english_scope_supported("Marie Dupont rédigea rapport complet conservant chronologie exacte nécessaire.")
    assert not english_scope_supported(
        "Giulia Rossi redasse rapporto completo mantenendo cronologia esatta necessaria."
    )
    assert english_scope_supported("El Paso, Los Angeles, and La Jolla appear throughout this report.")
    assert english_scope_supported("Summarize.")
    assert english_scope_supported("List roles.")
    assert english_scope_supported("List dates.")
    assert not english_scope_supported("Resume este informe.")


def test_task_aware_entity_tokenization_keeps_categories_and_respects_conflicts() -> None:
    quote = "14 Jun — Laurent Hotel, Montreal — $612.00"
    assert tokenizable_specifics(quote, ["14 Jun", "$612.00"]) == ["Laurent", "Montreal"]
    assert tokenizable_specifics(quote, [quote]) == []
    assert tokenizable_specifics("This agreement begins in Raleigh.", ["2025"]) == ["Raleigh"]


def test_utility_rejects_adjacent_determiners_at_patch_boundary() -> None:
    original = "The subject won the 2019 Northshore Civic Data Prize after sustained public records work."
    quote = ground_quote(original, "2019 Northshore Civic Data Prize")
    proposed = apply_exact_patch(original, quote, "a regional civic data award")
    ledger = check_utility(
        previous=original,
        proposed=proposed,
        original_sanitized=original,
        pins=["public records work"],
        expected_tokens=[],
        authorized_quote=quote,
        replacement="a regional civic data award",
    )
    assert not ledger.accepted
    assert ledger.heuristic_warnings == ["Patch creates adjacent determiners at the edit boundary."]


def test_utility_rejects_broken_sentence_boundaries() -> None:
    original = "Context remains useful. In 2014, the subject received a distinctive award. Next fact remains."
    quote = ground_quote(original, "In 2014, the subject received a distinctive award.")
    replacement = "received a regional award"
    proposed = apply_exact_patch(original, quote, replacement)
    ledger = check_utility(
        previous=original,
        proposed=proposed,
        original_sanitized=original,
        pins=["Next fact remains."],
        expected_tokens=[],
        authorized_quote=quote,
        replacement=replacement,
    )
    assert not ledger.accepted
    assert ledger.heuristic_warnings == [
        "Patch removes sentence-boundary punctuation.",
        "Patch breaks sentence-initial capitalization.",
        "Patch appears to remove the sentence subject.",
    ]


def test_sentence_repair_adds_a_neutral_subject_and_preserves_boundaries() -> None:
    clue = "In 2014, she became the first woman to receive the Fields Medal."
    assert repair_sentence_replacement(clue, "received a major mathematics award") == (
        "The subject received a major mathematics award."
    )
    assert repair_sentence_replacement(clue, "She received a major mathematics award.") == (
        "The subject received a major mathematics award."
    )
    assert repair_sentence_replacement("The subject grew up in Hyderabad.", "Grew up in India.") == (
        "The subject grew up in India."
    )


def test_utility_budget_allows_bounded_stack_edits_without_permitting_mush() -> None:
    assert MAX_PER_PASS_EDIT_RATIO == 0.20
    assert MAX_CUMULATIVE_EDIT_RATIO == 0.40
    original = "A" * 100
    quote = ground_quote(original, "A" * 20)
    assert quote.status == "ambiguous"

    original = "0123456789" * 10
    quote = ground_quote(original, original[:20])
    assert quote.status == "ambiguous"

    original = "abcdefghijklmnopqrst" + ("x" * 80)
    quote = ground_quote(original, "abcdefghijklmnopqrst")
    proposed = apply_exact_patch(original, quote, "ABCDEFGHIJKLMNOPQRST")
    ledger = check_utility(
        previous=original,
        proposed=proposed,
        original_sanitized=original,
        pins=[],
        expected_tokens=[],
        authorized_quote=quote,
        replacement="ABCDEFGHIJKLMNOPQRST",
    )
    assert ledger.accepted
    assert ledger.per_pass_edit_ratio == 0.20

    too_large = apply_exact_patch(original, quote, "Z" * 21)
    rejected = check_utility(
        previous=original,
        proposed=too_large,
        original_sanitized=original,
        pins=[],
        expected_tokens=[],
        authorized_quote=quote,
        replacement="Z" * 21,
    )
    assert not rejected.accepted
    assert "more than 20%" in rejected.reasons[0]


def test_recorded_demo_uses_a_grammatical_accepted_patch() -> None:
    from cloak.demo import DEMO_FINAL, DEMO_SURROGATE, recorded_demo

    assert "won the a " not in DEMO_FINAL
    assert DEMO_SURROGATE in DEMO_FINAL
    assert "[[CX_" not in DEMO_FINAL
    events = recorded_demo()["events"]
    accepted = next(event for event in events if event["phase"] == "patch_accepted")
    assert accepted["utility"]["accepted"] is True
    assert accepted["utility"]["heuristic_warnings"] == []


def test_candidate_hash_and_edit_ratios_are_deterministic() -> None:
    original = "A sufficiently long document with a distinctive professional award and context."
    first = candidate_from_text(original, original_text=original, pass_number=0, parent_sha256=None)
    second = candidate_from_text(
        original.replace("distinctive", "regional"),
        original_text=original,
        pass_number=1,
        parent_sha256=first.sha256,
        previous_text=original,
    )
    assert first.sha256 != second.sha256
    assert second.parent_sha256 == first.sha256
    assert 0 < second.per_pass_edit_ratio < 0.15
