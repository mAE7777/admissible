from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field

from admissible.models import (
    ConfirmSessionRequest,
    ConfirmSessionResponse,
    IdentifierCandidate,
    ProtectedSubject,
    SanitizedCandidate,
    SessionCreateResponse,
)
from admissible.privacy import candidate_from_text, english_scope_supported, normalize_input
from admissible.vault import LocalVault

EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE = re.compile(r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\w)")
SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
PERSON_ATOM = r"[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'’\-]{1,30}"
PERSON = re.compile(rf"\b(?:{PERSON_ATOM})(?:\s+{PERSON_ATOM}){{1,3}}\b")
STREET_WORD = r"[A-Za-z0-9][A-Za-z0-9'’\-]*\.?"
# A locality tail: ", Portland, OR 97205" or ", Reno NV 89501" (the comma before the state is
# optional in common usage, and omitting it previously left the tail unmatched).
LOCALITY_TAIL = (
    r"(?:,[ \t]*[A-Za-z][A-Za-z .'-]{0,40},?[ \t]*[A-Z]{2}[ \t]+\d{5}(?:-\d{4})?)?"
)
ADDRESS = re.compile(
    r"(?<!\w)(?:"
    # Street form: 742 Cedar Avenue[, Portland, OR 97205]
    rf"\d{{1,6}}[ \t]+(?:{STREET_WORD}[ \t]+){{1,8}}"
    r"(?:Street|Avenue|Boulevard|Parkway|Terrace|Circle|Highway|Road|Lane|Drive|Court|"
    r"St|Ave|Blvd|Pkwy|Ter|Cir|Hwy|Rd|Ln|Dr|Ct|Way)\b\.?"
    rf"{LOCALITY_TAIL}"
    r"|"
    # Post-office-box form: PO Box 4417[, Reno NV 89501]. A real, common mailing identifier that
    # the street-suffix form structurally cannot match.
    rf"(?:P\.?[ \t]?O\.?|Post[ \t]+Office)[ \t]+Box[ \t]+\d{{1,8}}{LOCALITY_TAIL}"
    r")",
    re.IGNORECASE,
)
# Tokens that appear inside postal/address fragments and are never personal-name parts. Used to
# stop address debris from being offered as a Person once the address patterns decline it.
US_STATE_CODES = frozenset(
    "AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ "
    "NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC PR VI GU AS MP".split()
)
NON_NAME_TOKENS = frozenset(
    {"po", "p.o", "box", "suite", "ste", "apt", "apartment", "unit", "floor", "fl", "rm", "room",
     "building", "bldg", "attn", "care", "c/o", "mailstop", "postal", "zip"}
)
ORGANIZATION = re.compile(
    r"\b(?:[A-Z][A-Za-z'’&.-]*\s+){1,6}"
    r"(?:Clinic|College|Company|Cooperative|Corporation|Corp\.?|Foundation|Group|Hospital|Hotel|"
    r"Institute|LLC|Ltd\.?|Municipality|Office|School|Systems?)\b"
)
ORGANIZATION_ATOM = r"(?:[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ0-9'’&\-]{0,40}|&)"
ORGANIZATION_ROLE = (
    r"administrator|analyst|associate|attorney|chief|consultant|coordinator|counsel|designer|director|"
    r"doctor|employee|engineer|executive|lead|manager|nurse|officer|operator|partner|researcher|specialist|"
    r"supervisor|teacher|technician|worker"
)
ORGANIZATION_AFTER_WORK_CUE = re.compile(
    rf"\b(?:(?i:{ORGANIZATION_ROLE})\s+(?i:at|for)|"
    rf"(?i:employed by|works? (?:at|for)|working (?:at|for)|joined))\s+"
    rf"(?P<organization>{ORGANIZATION_ATOM}(?:\s+{ORGANIZATION_ATOM}){{0,5}})"
    r"(?=\s+(?i:in|on|as|where|which|that|who|and|but|from|during|after|before|since|until)\b|[,.;:!?]|$)"
)
ORGANIZATION_POSSESSIVE = re.compile(
    rf"\b(?P<organization>{ORGANIZATION_ATOM}(?:\s+{ORGANIZATION_ATOM}){{0,5}})['’]s\s+"
    rf"(?i:{ORGANIZATION_ROLE})\b"
)
IDENTIFIER_CODE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Z][A-Z0-9]{1,8}(?:-[A-Z0-9]+){1,4}|\d{4}-\d{2}-\d{4})(?![A-Za-z0-9])"
)
PERSON_TITLE = re.compile(r"^(?:Mr|Mrs|Ms|Miss|Dr|Mx)\.?\s+", re.IGNORECASE)
PERSON_PART = re.compile(r"^[^\W\d_](?:[^\W\d_]|['’\-]){0,39}$", re.UNICODE)


def _name_parts(value: str) -> list[str]:
    clean = PERSON_TITLE.sub("", value.strip())
    parts = [part.rstrip(".") for part in clean.split()]
    if not 1 <= len(parts) <= 4:
        return []
    if any(not PERSON_PART.fullmatch(part) for part in parts):
        return []
    return [part.casefold() for part in parts]


def _alias_matches_canonical(alias: str, canonical: str) -> bool:
    alias_parts = _name_parts(alias)
    canonical_parts = _name_parts(canonical)
    if not alias_parts or not canonical_parts:
        return False
    return any(
        alias_part == canonical_part
        or (len(alias_part) == 1 and canonical_part.startswith(alias_part))
        for alias_part in alias_parts
        for canonical_part in canonical_parts
    )


def _plausible_person(value: str) -> bool:
    """Reject address/postal debris that the Person pattern would otherwise offer as a name.

    The Person pattern matches any run of capitalised words, so when an address form declines a
    fragment (a PO box, a bare "City ST"), its pieces resurface as person candidates. A junk
    candidate on the confirmation surface erodes trust in every real candidate beside it, so the
    filter is deliberately narrow: only tokens that are never personal-name parts.
    """
    parts = [part.rstrip(".") for part in PERSON_TITLE.sub("", value.strip()).split()]
    if not parts:
        return False
    return not any(part.casefold() in NON_NAME_TOKENS or part in US_STATE_CODES for part in parts)


def _organization_spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for match in ORGANIZATION.finditer(text):
        spans.append((*match.span(), match.group(0)))
    for pattern in (ORGANIZATION_AFTER_WORK_CUE, ORGANIZATION_POSSESSIVE):
        for match in pattern.finditer(text):
            start, end = match.span("organization")
            spans.append((start, end, match.group("organization")))
    return list(dict.fromkeys(spans))


@dataclass
class Session:
    session_id: str
    raw_text: str
    suggested_identifiers: set[str] = field(default_factory=set)
    suggested_identifier_labels: dict[str, str] = field(default_factory=dict)
    suggested_subjects: set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.monotonic)
    updated_at: float = field(default_factory=time.monotonic)
    subject: ProtectedSubject | None = None
    task: str = ""
    pins: list[str] = field(default_factory=list)
    task_facts: list[str] = field(default_factory=list)
    vault: LocalVault = field(default_factory=LocalVault)
    original_sanitized: str | None = None
    candidate: SanitizedCandidate | None = None
    last_run_id: str | None = None
    last_evidence: list[str] = field(default_factory=list)
    causal_candidates: dict[str, SanitizedCandidate] = field(default_factory=dict)
    causal_base_ranks: dict[str, int] = field(default_factory=dict)
    attacker_calls_used: int = 0

    def touch(self) -> None:
        self.updated_at = time.monotonic()


class SessionStore:
    def __init__(self, ttl_seconds: int = 3600) -> None:
        self.ttl_seconds = ttl_seconds
        self._sessions: dict[str, Session] = {}

    def _purge(self) -> None:
        now = time.monotonic()
        expired = [
            session_id for session_id, session in self._sessions.items() if now - session.updated_at > self.ttl_seconds
        ]
        for session_id in expired:
            del self._sessions[session_id]

    def create(self, text: str) -> SessionCreateResponse:
        self._purge()
        normalized = normalize_input(text)
        session_id = uuid.uuid4().hex
        identifiers = suggest_identifiers(normalized)
        subjects = list(dict.fromkeys(candidate.value for candidate in identifiers if candidate.label == "Person"))
        self._sessions[session_id] = Session(
            session_id=session_id,
            raw_text=normalized,
            suggested_identifiers={candidate.value for candidate in identifiers},
            suggested_identifier_labels={candidate.value: candidate.label for candidate in identifiers},
            suggested_subjects=set(subjects[:8]),
        )
        return SessionCreateResponse(
            session_id=session_id,
            normalized_text=normalized,
            char_count=len(normalized),
            subject_suggestions=subjects[:8],
            identifier_candidates=identifiers,
        )

    def get(self, session_id: str) -> Session:
        self._purge()
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError("Session expired or not found.")
        session.touch()
        return session

    def confirm(self, session_id: str, request: ConfirmSessionRequest) -> ConfirmSessionResponse:
        session = self.get(session_id)
        if not english_scope_supported(session.raw_text) or not english_scope_supported(request.task):
            raise ValueError("Admissible currently supports English documents and tasks only.")
        aliases = [request.subject.canonical_identity, *request.subject.aliases]
        if request.subject.canonical_identity not in session.suggested_subjects:
            raise ValueError("The protected subject must come from Admissible's local person suggestions.")
        invalid_aliases = [
            alias
            for alias in request.subject.aliases
            if not _alias_matches_canonical(alias, request.subject.canonical_identity)
        ]
        if invalid_aliases:
            raise ValueError("Every alias must be name-like and share a name component with the protected subject.")
        missing_aliases = [alias for alias in aliases if alias not in session.raw_text]
        if missing_aliases:
            raise ValueError("The protected subject and every alias must occur exactly in the document.")
        missing_ids = [value for value in request.identifiers if value not in session.raw_text]
        if missing_ids:
            raise ValueError("Every confirmed identifier must occur exactly in the document.")
        unsupported_ids = [value for value in request.identifiers if value not in session.suggested_identifiers]
        if unsupported_ids:
            raise ValueError("Confirmed identifiers must come from Admissible's local identifier suggestions.")
        session.subject = request.subject
        session.task = request.task
        sanitized = session.vault.sanitize(
            session.raw_text,
            aliases,
            request.identifiers,
            identifier_labels={value: session.suggested_identifier_labels[value] for value in request.identifiers},
        )
        missing_pins = [pin for pin in request.pins if pin not in sanitized]
        if missing_pins:
            raise ValueError("Pins must remain exact after identifier substitution.")
        session.pins = request.pins
        session.task_facts = []
        session.original_sanitized = sanitized
        session.candidate = candidate_from_text(
            sanitized,
            original_text=sanitized,
            pass_number=0,
            parent_sha256=None,
            restore_handles=session.vault.known_handles,
        )
        return ConfirmSessionResponse(
            session_id=session_id,
            candidate=session.candidate,
            confirmed_identifiers=len(request.identifiers),
            confirmed_pins=len(request.pins),
        )

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)


def suggest_identifiers(text: str) -> list[IdentifierCandidate]:
    found: list[tuple[str, str, int, int]] = []
    for label, pattern in (
        ("Email", EMAIL),
        ("Phone", PHONE),
        ("SSN", SSN),
        ("Address", ADDRESS),
        ("Identifier", IDENTIFIER_CODE),
    ):
        for match in pattern.finditer(text):
            found.append((label, match.group(0), *match.span()))
    found.extend(("Organization", value, start, end) for start, end, value in _organization_spans(text))
    protected_spans = [(start, end) for label, _value, start, end in found if label in {"Address", "Organization"}]
    for match in PERSON.finditer(text):
        start, end = match.span()
        if any(start >= protected_start and end <= protected_end for protected_start, protected_end in protected_spans):
            continue
        if not _plausible_person(match.group(0)):
            continue
        found.append(("Person", match.group(0), start, end))
    unique: list[IdentifierCandidate] = []
    labeled_values = list(dict.fromkeys((label, value) for label, value, _start, _end in found))
    for index, (label, value) in enumerate(labeled_values):
        unique.append(
            IdentifierCandidate(
                candidate_id=f"id-{index}",
                label=label,
                value=value,
                occurrence_count=text.count(value),
            )
        )
    return unique[:100]
