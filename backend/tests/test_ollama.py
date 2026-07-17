from __future__ import annotations

from cloak.services.ollama import OllamaAnonymizer


def test_replacement_contract_rejects_token_contamination_and_unbounded_phrases() -> None:
    clue = "developed influential work in hyperbolic geometry and dynamical systems"
    token = "[[CX_MFRGGZDFMZTWQ2LK_4d2c6a1f]]"  # noqa: S105 - synthetic opaque token
    assert OllamaAnonymizer._replacement_error(clue, token, []) == "opaque token mismatch"
    assert OllamaAnonymizer._replacement_error(clue, "advanced work", []) == "replacement must contain 3 to 24 words"
    assert (
        OllamaAnonymizer._replacement_error(clue, "detail " * 25, [])
        == "replacement must contain 3 to 24 words"
    )
    assert OllamaAnonymizer._replacement_error(clue, "did influential work in advanced mathematics", []) is None


def test_replacement_contract_preserves_tokens_when_the_clue_contains_them() -> None:
    token = "[[CX_MFRGGZDFMZTWQ2LK_4d2c6a1f]]"  # noqa: S105 - synthetic opaque token
    clue = f"{token} won a rare regional prize"
    assert OllamaAnonymizer._replacement_error(clue, "won a general professional award", []) == "opaque token mismatch"
    assert OllamaAnonymizer._replacement_error(clue, f"{token} received a professional award", []) is None


def test_replacement_contract_removes_uniqueness_instead_of_rephrasing_it() -> None:
    clue = "first woman to receive the Fields Medal"
    assert (
        OllamaAnonymizer._replacement_error(clue, "first female recipient of highest math award", [])
        == "remove all uniqueness and demographic markers"
    )
    assert (
        OllamaAnonymizer._replacement_error(clue, "earliest woman to win a mathematics prize", [])
        == "remove all uniqueness and demographic markers"
    )
    assert OllamaAnonymizer._replacement_error(clue, "received a major mathematics award", []) is None


def test_replacement_contract_preserves_complete_sentence_boundaries() -> None:
    clue = "In 2014, she became the first woman to receive the Fields Medal."
    assert (
        OllamaAnonymizer._replacement_error(clue, "received a major mathematics award", [])
        == "preserve sentence-ending punctuation"
    )
    assert OllamaAnonymizer._replacement_error(clue, "Received a major mathematics award.", []) is None


def test_replacement_contract_rejects_new_proper_names_and_acronyms() -> None:
    clue = "The subject grew up in Hyderabad and later joined a Redmond software company."
    assert (
        OllamaAnonymizer._replacement_error(clue, "The subject grew up in India and joined an organization.", [])
        == "replacement introduces a proper name or acronym"
    )
    assert (
        OllamaAnonymizer._replacement_error(clue, "The subject later joined an AI organization.", [])
        == "replacement introduces a proper name or acronym"
    )
    assert OllamaAnonymizer._replacement_error(clue, "The subject later joined a broad organization.", []) is None


def test_replacement_contract_allows_tokenizing_only_the_proper_name_atom() -> None:
    clue = "14 Jun — Laurent Hotel, Montreal — $612.00"
    assert OllamaAnonymizer._replacement_error(clue, clue, ["Laurent", "Montreal"]) is None
    assert (
        OllamaAnonymizer._replacement_error(clue, clue, ["$612.00"])
        == "token values must be short proper-name text"
    )


def test_revision_contract_cannot_reintroduce_removed_source_details() -> None:
    original = "The subject used cricket as a management metaphor at a software company."
    prior = "The subject used an activity to describe work at an organization."
    assert (
        OllamaAnonymizer._revision_error(
            original,
            prior,
            "The subject used cricket as a management metaphor at an organization.",
        )
        == "revision reintroduces removed source detail (cricket, management, metaphor)"
    )
    assert (
        OllamaAnonymizer._revision_error(
            original,
            prior,
            "The subject drew on personal experience while working at an organization.",
        )
        is None
    )
