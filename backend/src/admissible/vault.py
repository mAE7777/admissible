from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections import Counter
from dataclasses import dataclass, field

from admissible.models import RestoreResult
from admissible.privacy import LOOSE_TOKEN_PATTERN, TOKEN_PATTERN

PERSON_FIRST_NAMES = (
    "Avery",
    "Cameron",
    "Casey",
    "Devon",
    "Elliot",
    "Emery",
    "Hayden",
    "Jamie",
    "Jordan",
    "Lane",
    "Morgan",
    "Parker",
    "Quinn",
    "Reese",
    "Riley",
    "Robin",
    "Rowan",
    "Sage",
    "Sam",
    "Taylor",
)
PERSON_LAST_NAMES = (
    "Alden",
    "Bellamy",
    "Carver",
    "Dalton",
    "Ellery",
    "Finch",
    "Grayson",
    "Hale",
    "Ives",
    "Kendall",
    "Langley",
    "Mercer",
    "North",
    "Perry",
    "Quincy",
    "Reeve",
    "Sawyer",
    "Thorne",
    "Vale",
    "Winslow",
)
ORGANIZATION_PREFIXES = (
    "Alder",
    "Bluehaven",
    "Cedarstone",
    "Clearwater",
    "Everfield",
    "Fairmont",
    "Granite",
    "Harborstone",
    "Ironwood",
    "Juniper",
    "Keystone",
    "Lakeview",
    "Meadow",
    "Northstar",
    "Oakridge",
    "Pinecrest",
    "Redwood",
    "Silverbrook",
    "Stonebridge",
    "Westfield",
)
PLACE_NAMES = (
    "Ashford",
    "Brookfield",
    "Cedar Falls",
    "Clearwater",
    "Fairview",
    "Glenhaven",
    "Lakewood",
    "Maple Crossing",
    "Northfield",
    "Oakridge",
    "Pinehurst",
    "Riverton",
    "Stonehaven",
    "Westhaven",
)
STREET_NAMES = (
    "Alder Lane",
    "Birch Avenue",
    "Cedar Street",
    "Juniper Road",
    "Maple Court",
    "Oak Terrace",
    "Pine Way",
    "Willow Drive",
)

EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE = re.compile(r"^(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}$")
SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
ADDRESS = re.compile(
    r"^\d{1,6}\s+.+?(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Way)\b",
    re.IGNORECASE,
)
ORGANIZATION_CUE = re.compile(
    r"\b(?:clinic|college|company|cooperative|corporation|corp\.?|employer|foundation|group|hospital|hotel|"
    r"institute|llc|ltd\.?|municipality|office|school|systems?)\b",
    re.IGNORECASE,
)
PERSON_TITLE = re.compile(r"^(Mr|Mrs|Ms|Miss|Dr|Mx)\.?\s+", re.IGNORECASE)
PERSON_WORD = re.compile(r"^[A-Z][A-Za-z'’-]{1,30}$")


def _casefold_spans(text: str, value: str) -> list[tuple[int, int]]:
    target = value.casefold()
    if not target:
        return []
    folded: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for index, character in enumerate(text):
        expansion = character.casefold()
        folded.extend(expansion)
        starts.extend([index] * len(expansion))
        ends.extend([index + 1] * len(expansion))
    folded_text = "".join(folded)
    spans: list[tuple[int, int]] = []
    cursor = 0
    while True:
        folded_start = folded_text.find(target, cursor)
        if folded_start < 0:
            return spans
        folded_end = folded_start + len(target)
        begins_on_boundary = folded_start == 0 or starts[folded_start] != starts[folded_start - 1]
        ends_on_boundary = folded_end == len(starts) or starts[folded_end] != starts[folded_end - 1]
        if begins_on_boundary and ends_on_boundary:
            spans.append((starts[folded_start], ends[folded_end - 1]))
        cursor = folded_start + 1


def _preserve_case(source: str, replacement: str) -> str:
    letters = "".join(character for character in source if character.isalpha())
    if letters and letters.isupper():
        return replacement.upper()
    if letters and letters.islower():
        return replacement.lower()
    return replacement


def extract_restore_handles(text: str, handles: list[str] | tuple[str, ...] | set[str]) -> list[str]:
    """Return non-overlapping known surrogate occurrences, preferring the longest surface."""
    ordered = sorted({handle for handle in handles if handle}, key=lambda value: (-len(value), value))
    if not ordered:
        return []
    pattern = re.compile("|".join(re.escape(handle) for handle in ordered))
    return [match.group(0) for match in pattern.finditer(text)]


@dataclass
class LocalVault:
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    token_to_value: dict[str, str] = field(default_factory=dict)
    expected_counts: Counter[str] = field(default_factory=Counter)

    @property
    def known_handles(self) -> list[str]:
        return list(self.token_to_value)

    def handles_in_text(self, text: str) -> list[str]:
        return extract_restore_handles(text, self.known_handles)

    def _digest(self, label: str, *, salt: int = 0) -> bytes:
        return hmac.new(self.secret, f"{label}:{salt}".encode(), hashlib.sha256).digest()

    def _choice(self, label: str, values: tuple[str, ...], *, offset: int = 0, salt: int = 0) -> str:
        digest = self._digest(label, salt=salt)
        return values[digest[offset % len(digest)] % len(values)]

    def _person(self, label: str, *, salt: int = 0) -> tuple[str, str]:
        return (
            self._choice(f"{label}:first", PERSON_FIRST_NAMES, salt=salt),
            self._choice(f"{label}:last", PERSON_LAST_NAMES, offset=1, salt=salt),
        )

    def _subject_alias(self, alias: str, canonical: str, first: str, last: str) -> str:
        title_match = PERSON_TITLE.match(alias)
        if title_match:
            title = title_match.group(1)
            punctuation = "." if "." in title_match.group(0) else ""
            return f"{title}{punctuation} {last}"
        clean_alias = alias.strip()
        clean_canonical = PERSON_TITLE.sub("", canonical).strip()
        alias_words = clean_alias.replace(".", "").split()
        canonical_words = clean_canonical.replace(".", "").split()
        if clean_alias.casefold() == clean_canonical.casefold() and len(canonical_words) >= 3:
            middle = self._choice("protected-subject:middle", PERSON_FIRST_NAMES, offset=2)
            return _preserve_case(clean_alias, f"{first} {middle} {last}")
        if len(alias_words) == 1:
            if canonical_words and alias_words[0].casefold() == canonical_words[-1].casefold():
                return _preserve_case(clean_alias, last)
            return _preserve_case(clean_alias, first)
        if len(alias_words) == 2 and len(alias_words[0]) == 1:
            separator = ". " if "." in clean_alias else " "
            return f"{first[0]}{separator}{last}"
        return _preserve_case(clean_alias, f"{first} {last}")

    def _digits(self, label: str, count: int, *, salt: int = 0) -> str:
        digest = self._digest(label, salt=salt)
        return "".join(str(digest[index % len(digest)] % 10) for index in range(count))

    def _formatted_code(self, label: str, original: str, *, salt: int = 0) -> str:
        digest = self._digest(label, salt=salt)
        output: list[str] = []
        cursor = 0
        semantic_prefix = re.match(r"^[A-Za-z]{1,8}(?=-)", original)
        prefix_end = semantic_prefix.end() if semantic_prefix else 0
        for position, character in enumerate(original):
            if position < prefix_end:
                output.append(character)
                continue
            if character.isdigit():
                output.append(str(digest[cursor % len(digest)] % 10))
                cursor += 1
            elif character.isalpha():
                letter = chr(ord("A") + digest[cursor % len(digest)] % 26)
                output.append(letter if character.isupper() else letter.lower())
                cursor += 1
            else:
                output.append(character)
        return "".join(output)

    def _phone(self, label: str, original: str, *, salt: int = 0) -> str:
        suffix = 100 + int(self._digits(f"{label}:phone", 2, salt=salt))
        local = f"555-{suffix:04d}"
        if original.startswith("+1"):
            return f"+1 202-{local}"
        if "(" in original:
            return f"(202) {local}"
        if "." in original:
            return f"202.555.{suffix:04d}"
        return f"202-{local}"

    def _address(self, label: str, original: str, *, salt: int = 0) -> str:
        digest = self._digest(f"{label}:address", salt=salt)
        number = 100 + int.from_bytes(digest[:2], "big") % 9800
        street = self._choice(f"{label}:street", STREET_NAMES, salt=salt)
        city = self._choice(f"{label}:city", PLACE_NAMES, offset=1, salt=salt)
        state_match = re.search(r",\s*([A-Z]{2})(?:\s+\d{5}(?:-\d{4})?)?\s*$", original)
        if state_match:
            state = state_match.group(1)
            zip_code = f"{10000 + int.from_bytes(digest[2:4], 'big') % 89999:05d}"
            return f"{number} {street}, {city}, {state} {zip_code}"
        return f"{number} {street}, {city}"

    def _organization(self, label: str, original: str, *, salt: int = 0) -> str:
        prefix = self._choice(f"{label}:organization", ORGANIZATION_PREFIXES, salt=salt)
        first_word = re.search(r"[A-Za-z][A-Za-z'’-]*", original)
        if first_word is None:
            return f"{prefix} Services"
        return f"{original[: first_word.start()]}{prefix}{original[first_word.end() :]}"

    def _surrogate(
        self,
        label: str,
        original: str,
        *,
        subject_name: tuple[str, str] | None,
        identifier_type: str | None = None,
        salt: int = 0,
    ) -> str:
        normalized_type = identifier_type.casefold() if identifier_type else None
        if normalized_type == "email" or EMAIL.fullmatch(original):
            if subject_name is None:
                subject_name = self._person(label, salt=salt)
            local = f"{subject_name[0]}.{subject_name[1]}".casefold()
            return f"{local}@example.invalid"
        if normalized_type == "phone" or PHONE.fullmatch(original):
            return self._phone(label, original, salt=salt)
        if normalized_type in {"ssn", "identifier"} or SSN.fullmatch(original):
            return self._formatted_code(label, original, salt=salt)
        if normalized_type == "address" or ADDRESS.match(original):
            return self._address(label, original, salt=salt)
        if normalized_type == "organization" or ORGANIZATION_CUE.search(original):
            return self._organization(label, original, salt=salt)
        words = original.split()
        if normalized_type == "person" or (
            1 < len(words) <= 4 and all(PERSON_WORD.fullmatch(word.strip(".,")) for word in words)
        ):
            first, last = self._person(label, salt=salt)
            return f"{first} {last}"
        if len(words) == 1 and PERSON_WORD.fullmatch(words[0].strip(".,")):
            return self._choice(f"{label}:place", PLACE_NAMES, salt=salt)
        return self._formatted_code(label, original, salt=salt)

    def _unique(
        self,
        label: str,
        original: str,
        source: str,
        *,
        subject_name: tuple[str, str] | None = None,
        identifier_type: str | None = None,
        reserved: set[str] | None = None,
    ) -> str:
        unavailable = reserved or set()
        for salt in range(100):
            value = self._surrogate(
                label,
                original,
                subject_name=subject_name,
                identifier_type=identifier_type,
                salt=salt,
            )
            if (
                value.casefold() not in source.casefold()
                and value not in self.token_to_value
                and value not in unavailable
            ):
                return value
        raise RuntimeError("Could not create a collision-free local surrogate.")

    def sanitize(
        self,
        text: str,
        subject_aliases: list[str],
        identifiers: list[str],
        *,
        identifier_labels: dict[str, str] | None = None,
    ) -> str:
        aliases = list(dict.fromkeys(alias for alias in subject_aliases if alias))
        alias_keys = {alias.casefold() for alias in aliases}
        confirmed_labels = identifier_labels or {}
        canonical = aliases[0] if aliases else "Protected subject"
        subject_name = self._person("protected-subject")
        values: list[tuple[str, str, str, str | None]] = []
        for index, alias in enumerate(aliases):
            values.append(
                (
                    "subject",
                    f"protected-subject-{index}",
                    alias,
                    "Person",
                )
            )
        values.extend(
            ("identifier", f"identifier-{index}", value, confirmed_labels.get(value))
            for index, value in enumerate(identifiers)
            if value and value.casefold() not in alias_keys
        )

        label_surrogates: dict[str, str] = {}
        identifier_types: dict[str, str | None] = {}
        reserved_surrogates: set[str] = set()
        for kind, label, value, identifier_type in values:
            identifier_types[label] = identifier_type
            if kind == "subject":
                label_surrogates[label] = self._subject_alias(value, canonical, *subject_name)
            else:
                label_surrogates[label] = self._unique(
                    label,
                    value,
                    text,
                    subject_name=subject_name,
                    identifier_type=identifier_type,
                    reserved=reserved_surrogates,
                )
            reserved_surrogates.add(label_surrogates[label])

        candidate_spans: list[tuple[int, int, str]] = []
        for _kind, label, value, _identifier_type in values:
            candidate_spans.extend((start, end, label) for start, end in _casefold_spans(text, value))
        selected_spans: list[tuple[int, int, str]] = []
        cursor = 0
        for start, end, label in sorted(candidate_spans, key=lambda item: (item[0], -(item[1] - item[0]), item[2])):
            if start >= cursor:
                selected_spans.append((start, end, label))
                cursor = end

        surface_handles: dict[tuple[str, str], str] = {}
        sanitized_parts: list[str] = []
        cursor = 0
        for start, end, label in selected_spans:
            surface = text[start:end]
            key = (label, surface)
            handle = surface_handles.get(key)
            if handle is None:
                handle = _preserve_case(surface, label_surrogates[label])
                if handle in self.token_to_value and self.token_to_value[handle] != surface:
                    handle = self._unique(
                        f"{label}:{surface}",
                        surface,
                        text,
                        subject_name=subject_name,
                        identifier_type=identifier_types[label],
                    )
                surface_handles[key] = handle
                self.token_to_value[handle] = surface
            sanitized_parts.extend((text[cursor:start], handle))
            cursor = end
        sanitized_parts.append(text[cursor:])
        sanitized = "".join(sanitized_parts)
        self.expected_counts = Counter(self.handles_in_text(sanitized))
        return sanitized

    def stage_fragment_tokenization(self, fragment: str, values: list[str]) -> tuple[str, dict[str, str]]:
        """Prepare natural, restorable surrogates without mutating the live vault until acceptance."""
        clean_values = list(dict.fromkeys(value.strip() for value in values if value.strip()))
        if not clean_values:
            return fragment, {}
        staged: dict[str, str] = {}
        replacement = fragment
        for index, value in enumerate(sorted(clean_values, key=len, reverse=True)):
            if value not in fragment:
                raise ValueError("A proposed surrogate value is not inside the authorized clue.")
            surrogate = self._unique(
                f"inferred-identifier-{index}",
                value,
                fragment,
                reserved=set(staged),
            )
            replacement = replacement.replace(value, surrogate)
            staged[surrogate] = value
        return replacement, staged

    def commit_staged_tokens(self, staged: dict[str, str], candidate: str) -> None:
        if any(handle not in candidate for handle in staged):
            raise ValueError("A staged surrogate is missing from the accepted candidate.")
        self.token_to_value.update(staged)
        self.expected_counts = Counter(self.handles_in_text(candidate))

    def retain_candidate(self, candidate: str) -> None:
        retained = Counter(self.handles_in_text(candidate))
        self.token_to_value = {
            handle: value for handle, value in self.token_to_value.items() if handle in retained
        }
        self.expected_counts = retained

    def _likely_mutations(self, text: str, found: Counter[str]) -> dict[str, str]:
        mutations: dict[str, str] = {}
        for handle in self.token_to_value:
            expected = self.expected_counts[handle]
            if found[handle] >= expected or len(handle) < 6:
                continue
            width = len(handle)
            for start in range(len(text) - width + 1):
                end = start + width
                if handle[0].isalnum() and start > 0 and text[start - 1].isalnum():
                    continue
                if handle[-1].isalnum() and end < len(text) and text[end].isalnum():
                    continue
                candidate = text[start:end]
                different_characters = sum(a != b for a, b in zip(candidate, handle, strict=True))
                if different_characters == 1:
                    mutations[handle] = candidate
                    break
        return mutations

    def restore(self, text: str) -> RestoreResult:
        found = Counter(self.handles_in_text(text))
        likely_mutations = self._likely_mutations(text, found)
        missing = sorted(
            handle
            for handle, count in self.expected_counts.items()
            if found[handle] < count and handle not in likely_mutations
        )
        duplicated = sorted(handle for handle, count in found.items() if count > self.expected_counts[handle] > 0)
        mutated = sorted(likely_mutations.values())
        legacy_tokens = Counter(TOKEN_PATTERN.findall(text))
        loose_tokens = Counter(LOOSE_TOKEN_PATTERN.findall(text))
        unknown = sorted({*legacy_tokens, *loose_tokens} - set(self.token_to_value))

        handles = sorted(self.token_to_value, key=lambda value: (-len(value), value))
        restored_count = 0
        if handles:
            pattern = re.compile("|".join(re.escape(handle) for handle in handles))

            def replace(match: re.Match[str]) -> str:
                nonlocal restored_count
                restored_count += 1
                return self.token_to_value[match.group(0)]

            restored = pattern.sub(replace, text)
        else:
            restored = text
        return RestoreResult(
            restored_text=restored,
            restored_count=restored_count,
            missing_tokens=missing,
            duplicated_tokens=duplicated,
            mutated_tokens=mutated,
            unknown_tokens=unknown,
        )
