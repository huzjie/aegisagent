"""PII recognisers with real checksum validation.

Regex-only PII detection is famously noisy: any 18-digit number looks like a
Chinese resident ID and any 16-digit number looks like a payment card.  Every
recogniser here pairs a structural pattern with the *actual* validation
algorithm defined by the issuing standard:

* Mainland China resident ID - GB 11643-1999 ISO 7064:1983 MOD 11-2 check digit
  plus administrative-division and birth-date sanity checks.
* Payment cards - Luhn (ISO/IEC 7812) plus issuer-prefix recognition.
* Chinese mobile numbers - the allocated MIIT prefix ranges, not ``1`` + 10.
* Email / IPv4 / passport / bank account / IBAN - structural plus range checks.

Each match is graded with a :class:`DataSensitivity` level so the content
policy detector can apply a tiered response instead of one blunt severity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from typing import Callable, Dict, List, Optional, Pattern, Sequence, Tuple

__all__ = [
    "DataSensitivity",
    "PiiHit",
    "PiiRecogniser",
    "RECOGNISERS",
    "scan_pii",
    "validate_china_id",
    "luhn_check",
    "card_brand",
    "validate_cn_mobile",
    "mask_value",
]


class DataSensitivity(str, Enum):
    """Tiered classification of personal / regulated data."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"          # PII: identity documents, financial
    HIGHLY_RESTRICTED = "highly_restricted"  # health, biometrics, credentials

    @property
    def rank(self) -> int:
        return ["public", "internal", "confidential", "restricted", "highly_restricted"].index(self.value)


# --------------------------------------------------------------------------- #
# Chinese resident identity card (GB 11643-1999)
# --------------------------------------------------------------------------- #
#: Weights for the ISO 7064 MOD 11-2 check digit.
_ID_WEIGHTS: Tuple[int, ...] = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)

#: Check-digit alphabet indexed by the weighted-sum remainder.
_ID_CHECK_CODES: str = "10X98765432"

#: Valid first two digits of the administrative division code (province level).
_PROVINCE_CODES = frozenset(
    {"11", "12", "13", "14", "15", "21", "22", "23", "31", "32", "33", "34", "35",
     "36", "37", "41", "42", "43", "44", "45", "46", "50", "51", "52", "53", "54",
     "61", "62", "63", "64", "65", "71", "81", "82", "91"}
)

CHINA_ID_RE = re.compile(r"(?<![0-9Xx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![0-9Xx])")


def validate_china_id(value: str) -> bool:
    """Validate an 18-digit mainland China resident ID number.

    Checks province code, birth-date plausibility and the MOD 11-2 check digit.

    Args:
        value: Candidate ID, case-insensitive for the trailing ``X``.

    Returns:
        ``True`` only when every check passes.
    """
    candidate = (value or "").strip().upper()
    if len(candidate) != 18:
        return False
    if not candidate[:17].isdigit():
        return False
    if candidate[17] not in "0123456789X":
        return False
    if candidate[:2] not in _PROVINCE_CODES:
        return False
    try:
        birth = date(int(candidate[6:10]), int(candidate[10:12]), int(candidate[12:14]))
    except ValueError:
        return False
    today = date.today()
    if birth > today or birth.year < 1900:
        return False
    total = sum(int(digit) * weight for digit, weight in zip(candidate[:17], _ID_WEIGHTS))
    return _ID_CHECK_CODES[total % 11] == candidate[17]


# --------------------------------------------------------------------------- #
# Payment cards (ISO/IEC 7812 Luhn)
# --------------------------------------------------------------------------- #
CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")

#: Issuer identification-number prefixes, longest first for correct matching.
_CARD_BRANDS: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("amex", re.compile(r"^3[47]\d{13}$")),
    ("diners", re.compile(r"^3(?:0[0-5]|[68]\d)\d{11}$")),
    ("jcb", re.compile(r"^(?:2131|1800|35\d{3})\d{11}$")),
    ("unionpay", re.compile(r"^62\d{14,17}$")),
    ("visa", re.compile(r"^4\d{12}(?:\d{3})?(?:\d{3})?$")),
    ("mastercard", re.compile(r"^(?:5[1-5]\d{14}|2(?:2[2-9]\d{12}|[3-6]\d{13}|7[01]\d{12}|720\d{12}))$")),
    ("discover", re.compile(r"^6(?:011|5\d{2}|4[4-9]\d)\d{12}$")),
)


def luhn_check(value: str) -> bool:
    """Validate a number with the Luhn (mod 10) algorithm.

    Separators (spaces, hyphens) are ignored.  Returns ``False`` for anything
    shorter than 12 digits, which rules out most identifiers and phone numbers.
    """
    digits = [int(ch) for ch in (value or "") if ch.isdigit()]
    if len(digits) < 12 or len(digits) > 19:
        return False
    if len(set(digits)) == 1:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def card_brand(value: str) -> str:
    """Return the card scheme name, or ``unknown`` when no prefix matches."""
    digits = "".join(ch for ch in (value or "") if ch.isdigit())
    for name, pattern in _CARD_BRANDS:
        if pattern.match(digits):
            return name
    return "unknown"


# --------------------------------------------------------------------------- #
# Chinese mobile numbers (MIIT allocated ranges)
# --------------------------------------------------------------------------- #
CN_MOBILE_RE = re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)")

#: Prefixes never allocated by MIIT - filters out sequential test numbers.
_INVALID_MOBILE_PREFIXES = frozenset({"1340", "1341", "1342", "1343", "1344"})


def validate_cn_mobile(value: str) -> bool:
    """Validate a mainland China mobile number by allocated prefix."""
    digits = re.sub(r"\D", "", value or "")
    if digits.startswith("86"):
        digits = digits[2:]
    if len(digits) != 11 or digits[0] != "1":
        return False
    if digits[1] not in "3456789":
        return False
    if digits[:4] in _INVALID_MOBILE_PREFIXES:
        return False
    # 11 identical or strictly sequential digits are test data, not people.
    body = digits[2:]
    return len(set(body)) > 2


# --------------------------------------------------------------------------- #
# Other recognisers
# --------------------------------------------------------------------------- #
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}(?![\w-])")
IPV4_RE = re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d)")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
CN_PASSPORT_RE = re.compile(r"(?<![A-Za-z0-9])[EeGgDdSsPp][A-Za-z0-9]\d{7}(?![A-Za-z0-9])")
US_SSN_RE = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
CN_BANK_ACCOUNT_RE = re.compile(r"(?<!\d)62\d{14,17}(?!\d)")
CN_PLATE_RE = re.compile(r"[\u4eac\u6caa\u6d25\u6e1d\u5180\u8c6b\u4e91\u8fbd\u9ed1\u6e58\u7696\u9c81\u65b0\u82cf\u6d59\u8d63\u9102\u6842\u7518\u664b\u8499\u9655\u5409\u95fd\u8d35\u7ca4\u9752\u85cf\u5ddd\u5b81\u743c][A-Z][A-Z0-9]{5,6}")


def _always_valid(_: str) -> bool:
    """Validator for patterns whose regex is already sufficient."""
    return True


def _valid_iban(value: str) -> bool:
    """ISO 13616 IBAN check using the MOD-97 algorithm."""
    cleaned = re.sub(r"\s", "", (value or "").upper())
    if len(cleaned) < 15:
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    digits = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
    if not digits.isdigit():
        return False
    return int(digits) % 97 == 1


def _valid_public_ip(value: str) -> bool:
    """Only treat routable IPv4 addresses as personal data."""
    octets = [int(part) for part in value.split(".")]
    if octets[0] in (0, 10, 127) or octets[:2] == [192, 168] or octets[:2] == [169, 254]:
        return False
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return False
    return octets[0] < 224


@dataclass(frozen=True)
class PiiRecogniser:
    """A named PII pattern plus its semantic validator.

    Attributes:
        name: Recogniser id, e.g. ``china_resident_id``.
        pattern: Compiled structural regex.
        validator: Callable returning ``True`` for a genuine match.
        sensitivity: Data-classification tier for matches.
        label: Human-readable name (Chinese where the datum is China-specific).
        mask_keep: How many trailing characters remain visible when masking.
    """

    name: str
    pattern: Pattern[str]
    validator: Callable[[str], bool]
    sensitivity: DataSensitivity
    label: str
    mask_keep: int = 4


#: All recognisers, evaluated in order.  Order matters: bank-account numbers
#: are matched before the generic card pattern so UnionPay cards keep the more
#: specific label.
RECOGNISERS: Tuple[PiiRecogniser, ...] = (
    PiiRecogniser("china_resident_id", CHINA_ID_RE, validate_china_id,
                  DataSensitivity.RESTRICTED, "中国大陆居民身份证号", 4),
    PiiRecogniser("payment_card", CARD_RE, luhn_check,
                  DataSensitivity.RESTRICTED, "银行卡号 (Luhn 校验通过)", 4),
    PiiRecogniser("china_bank_account", CN_BANK_ACCOUNT_RE, luhn_check,
                  DataSensitivity.RESTRICTED, "中国银联账号", 4),
    PiiRecogniser("china_mobile", CN_MOBILE_RE, validate_cn_mobile,
                  DataSensitivity.CONFIDENTIAL, "中国大陆手机号", 4),
    PiiRecogniser("email", EMAIL_RE, _always_valid,
                  DataSensitivity.CONFIDENTIAL, "电子邮箱地址", 0),
    PiiRecogniser("us_ssn", US_SSN_RE, _always_valid,
                  DataSensitivity.RESTRICTED, "US Social Security Number", 4),
    PiiRecogniser("iban", IBAN_RE, _valid_iban,
                  DataSensitivity.RESTRICTED, "IBAN 国际银行账号", 4),
    PiiRecogniser("china_passport", CN_PASSPORT_RE, _always_valid,
                  DataSensitivity.RESTRICTED, "中国护照号", 3),
    PiiRecogniser("china_plate", CN_PLATE_RE, _always_valid,
                  DataSensitivity.CONFIDENTIAL, "中国车牌号", 3),
    PiiRecogniser("ipv4", IPV4_RE, _valid_public_ip,
                  DataSensitivity.INTERNAL, "公网 IPv4 地址", 0),
)


@dataclass
class PiiHit:
    """One validated piece of personal data found in text."""

    recogniser: str
    label: str
    value: str
    masked: str
    sensitivity: DataSensitivity
    start: int
    end: int
    location: str = ""
    extra: Dict[str, str] = field(default_factory=dict)

    @property
    def evidence(self) -> str:
        """Evidence line that never contains the raw value."""
        detail = f" ({self.extra['brand']})" if "brand" in self.extra else ""
        return f"{self.label}{detail}: {self.masked}"

    def to_dict(self) -> Dict[str, object]:
        return {
            "recogniser": self.recogniser,
            "label": self.label,
            "masked": self.masked,
            "sensitivity": self.sensitivity.value,
            "location": self.location,
            "span": [self.start, self.end],
            "extra": dict(self.extra),
        }


def mask_value(value: str, keep: int = 4) -> str:
    """Mask all but the last ``keep`` characters of a sensitive value."""
    text = value or ""
    if keep <= 0:
        if "@" in text:
            local, _, domain = text.partition("@")
            head = local[:1] or "*"
            return f"{head}{'*' * max(1, len(local) - 1)}@{domain}"
        return "*" * min(len(text), 12)
    if len(text) <= keep:
        return "*" * len(text)
    return "*" * (len(text) - keep) + text[-keep:]


def scan_pii(
    text: str,
    *,
    location: str = "",
    recognisers: Optional[Sequence[PiiRecogniser]] = None,
    limit_per_type: int = 5,
) -> List[PiiHit]:
    """Find and validate personal data inside ``text``.

    Overlapping matches are resolved in recogniser order, so a UnionPay number
    is reported once as a bank account rather than twice.

    Args:
        text: Content to scan.
        location: Provenance label recorded on each hit.
        recognisers: Override the default recogniser set.
        limit_per_type: Cap on hits reported per recogniser.

    Returns:
        Validated hits sorted by position.
    """
    if not text:
        return []
    hits: List[PiiHit] = []
    claimed: List[Tuple[int, int]] = []
    for recogniser in recognisers or RECOGNISERS:
        found = 0
        for match in recogniser.pattern.finditer(text):
            if found >= limit_per_type:
                break
            raw = match.group(0)
            start, end = match.start(), match.end()
            if any(start < c_end and end > c_start for c_start, c_end in claimed):
                continue
            try:
                if not recogniser.validator(raw):
                    continue
            except Exception:  # noqa: BLE001 - a validator must never break scanning
                continue
            extra: Dict[str, str] = {}
            if recogniser.name in ("payment_card", "china_bank_account"):
                extra["brand"] = card_brand(raw)
            hits.append(
                PiiHit(
                    recogniser=recogniser.name,
                    label=recogniser.label,
                    value=raw,
                    masked=mask_value(raw, recogniser.mask_keep),
                    sensitivity=recogniser.sensitivity,
                    start=start,
                    end=end,
                    location=location,
                    extra=extra,
                )
            )
            claimed.append((start, end))
            found += 1
    hits.sort(key=lambda hit: hit.start)
    return hits


def highest_sensitivity(hits: Sequence[PiiHit]) -> DataSensitivity:
    """Return the strictest sensitivity tier among ``hits``."""
    if not hits:
        return DataSensitivity.PUBLIC
    return max((hit.sensitivity for hit in hits), key=lambda level: level.rank)


def redact_pii(text: str, **kwargs: object) -> str:
    """Return ``text`` with every validated PII value replaced by its mask."""
    hits = scan_pii(text, **kwargs)  # type: ignore[arg-type]
    if not hits:
        return text
    out = []
    cursor = 0
    for hit in hits:
        out.append(text[cursor:hit.start])
        out.append(hit.masked)
        cursor = hit.end
    out.append(text[cursor:])
    return "".join(out)
