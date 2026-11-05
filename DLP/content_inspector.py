import os
import re
import hashlib

class ContentInspector:
    """
    Industry-Grade Content-Aware Data Loss Prevention (DLP) Engine.
    Inspects files transferred to or found on USB storage devices for:
    1. Cryptographic Private Keys and SSL Certificates
    2. Cloud & API Credentials (AWS, GitHub, Google Cloud, Slack)
    3. Payment Card Information (PCI-DSS) with Luhn Algorithm validation
    4. Enterprise Confidentiality Markings & Trade Secrets
    5. High-Risk Database Dumps and Sensitive Credentials Files
    """

    # Maximum file size to inspect in memory (e.g., 5 MB to keep agent fast)
    MAX_INSPECT_BYTES = 5 * 1024 * 1024

    # High-Risk Extensions automatically flagged
    HIGH_RISK_EXTENSIONS = {
        '.sql', '.dump', '.bak', '.kdbx', '.pem', '.key', '.pkcs12',
        '.pfx', '.id_rsa', '.ovpn', '.shadow', '.htpasswd'
    }

    # Regex signatures for Cloud & API Keys
    API_KEY_PATTERNS = [
        ("AWS Access Key ID", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
        ("GitHub Token", re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,255}\b')),
        ("Google Cloud API Key", re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b')),
        ("Slack Token", re.compile(r'\bxox[baprs]-[0-9a-zA-Z-]{10,64}\b')),
        ("Private Key Header", re.compile(r'-----BEGIN\s+(RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE KEY-----')),
    ]

    # Confidentiality markings
    CONFIDENTIAL_PATTERNS = re.compile(
        r'\b(CONFIDENTIAL|STRICTLY\s+CONFIDENTIAL|PROPRIETARY\s+INFORMATION|INTERNAL\s+USE\s+ONLY|TRADE\s+SECRET)\b',
        re.IGNORECASE
    )

    # Credit card regex (Visa, Mastercard, Amex, Discover)
    CREDIT_CARD_REGEX = re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    )

    @staticmethod
    def luhn_checksum(card_number: str) -> bool:
        """Validates potential credit card numbers using the standard Luhn Algorithm."""
        digits = [int(d) for d in card_number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    @classmethod
    def calculate_sha256(cls, file_path: str) -> str:
        """Computes cryptographic SHA-256 hash of a file for forensic auditing."""
        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return "HASH_UNAVAILABLE"

    @classmethod
    def inspect_file(cls, file_path: str) -> list:
        """
        Inspects a file for DLP violations.
        Returns a list of violation dictionaries:
        [{"rule": "AWS Access Key", "severity": "CRITICAL", "sample": "AKIA..."}, ...]
        """
        violations = []
        if not os.path.isfile(file_path):
            return violations

        _, ext = os.path.splitext(file_path.lower())

        # 1. High-Risk File Extension Check
        if ext in cls.HIGH_RISK_EXTENSIONS:
            violations.append({
                "rule": "High-Risk Sensitive Extension",
                "severity": "HIGH",
                "sample": f"Restricted file extension: {ext}"
            })

        # Skip binary files that are too large or media/archives to avoid CPU slowdown
        skip_extensions = {
            '.iso', '.vmdk', '.mp4', '.mkv', '.avi', '.mp3', '.wav',
            '.zip', '.tar', '.gz', '.7z', '.rar', '.exe', '.dll', '.bin'
        }
        if ext in skip_extensions:
            return violations

        try:
            size = os.path.getsize(file_path)
            if size > cls.MAX_INSPECT_BYTES or size == 0:
                return violations

            # Read sample content
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(cls.MAX_INSPECT_BYTES)

            # 2. Check for API / Private Keys
            for rule_name, pattern in cls.API_KEY_PATTERNS:
                matches = pattern.findall(content)
                if matches:
                    violations.append({
                        "rule": rule_name,
                        "severity": "CRITICAL",
                        "sample": f"Found {len(matches)} instance(s) of {rule_name}"
                    })

            # 3. Check for Credit Card Numbers with Luhn check
            potential_cards = cls.CREDIT_CARD_REGEX.findall(content)
            valid_cards = [c for c in potential_cards if cls.luhn_checksum(c)]
            if valid_cards:
                violations.append({
                    "rule": "Payment Card Data (PCI-DSS)",
                    "severity": "CRITICAL",
                    "sample": f"Detected {len(valid_cards)} valid payment card number(s)"
                })

            # 4. Check for Corporate Confidential Watermarks
            conf_matches = cls.CONFIDENTIAL_PATTERNS.findall(content)
            if conf_matches:
                violations.append({
                    "rule": "Corporate Confidential Marking",
                    "severity": "MEDIUM",
                    "sample": f"Found watermark: {conf_matches[0].upper()}"
                })

        except Exception as e:
            # File read / locked error
            pass

        return violations

