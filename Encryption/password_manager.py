import os
import base64
import hmac
import hashlib

# Check for Argon2id
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    HAS_ARGON2 = True
    _argon2_hasher = PasswordHasher()
except ImportError:
    HAS_ARGON2 = False
    _argon2_hasher = None

# Check for Bcrypt
try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

# Check for Scrypt via cryptography
try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAS_SCRYPT = True
except ImportError:
    HAS_SCRYPT = False


class PasswordManager:
    """
    Secure password hashing and verification utility.
    Supports Argon2id, bcrypt, Scrypt, and PBKDF2-HMAC-SHA256.
    Provides constant-time verification and legacy SHA-256 upgrade path.
    """

    @classmethod
    def hash_password(cls, plain_password: str) -> str:
        """
        Hashes a password using the strongest available algorithm.
        Priority: Argon2id -> Bcrypt -> Scrypt -> PBKDF2-HMAC-SHA256 (600,000 iterations).
        """
        if not plain_password:
            raise ValueError("Password cannot be empty.")

        pwd_bytes = plain_password.encode("utf-8")

        if HAS_ARGON2:
            return _argon2_hasher.hash(plain_password)

        if HAS_BCRYPT:
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(pwd_bytes, salt)
            return hashed.decode("utf-8")

        if HAS_SCRYPT:
            salt = os.urandom(16)
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            derived = kdf.derive(pwd_bytes)
            b64_salt = base64.b64encode(salt).decode("ascii")
            b64_key = base64.b64encode(derived).decode("ascii")
            return f"$scrypt${b64_salt}${b64_key}"

        # NIST/OWASP compliant PBKDF2 fallback
        salt = os.urandom(16)
        iterations = 600000
        derived = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, iterations)
        b64_salt = base64.b64encode(salt).decode("ascii")
        b64_key = base64.b64encode(derived).decode("ascii")
        return f"$pbkdf2${iterations}${b64_salt}${b64_key}"

    @classmethod
    def verify_password(cls, plain_password: str, stored_hash: str) -> bool:
        """
        Verifies a plaintext password against a stored hash using timing-safe comparison.
        """
        if not plain_password or not stored_hash:
            return False

        pwd_bytes = plain_password.encode("utf-8")

        # 1. Argon2 verification
        if stored_hash.startswith("$argon2"):
            if HAS_ARGON2:
                try:
                    return _argon2_hasher.verify(stored_hash, plain_password)
                except Exception:
                    return False
            return False

        # 2. Bcrypt verification
        if stored_hash.startswith("$2a$") or stored_hash.startswith("$2b$") or stored_hash.startswith("$2y$"):
            if HAS_BCRYPT:
                try:
                    return bcrypt.checkpw(pwd_bytes, stored_hash.encode("utf-8"))
                except Exception:
                    return False
            return False

        # 3. Scrypt verification
        if stored_hash.startswith("$scrypt$"):
            try:
                parts = stored_hash.split("$")
                if len(parts) == 4:
                    salt = base64.b64decode(parts[2].encode("ascii"))
                    expected_key = base64.b64decode(parts[3].encode("ascii"))
                    if HAS_SCRYPT:
                        kdf = Scrypt(salt=salt, length=len(expected_key), n=2**14, r=8, p=1)
                        actual_key = kdf.derive(pwd_bytes)
                        return hmac.compare_digest(actual_key, expected_key)
            except Exception:
                return False

        # 4. PBKDF2 verification
        if stored_hash.startswith("$pbkdf2$"):
            try:
                parts = stored_hash.split("$")
                if len(parts) == 5:
                    iterations = int(parts[2])
                    salt = base64.b64decode(parts[3].encode("ascii"))
                    expected_key = base64.b64decode(parts[4].encode("ascii"))
                    actual_key = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, iterations)
                    return hmac.compare_digest(actual_key, expected_key)
            except Exception:
                return False

        # 5. Legacy SHA-256 fallback (for migrating old unsalted hashes)
        if len(stored_hash) == 64 and all(c in "0123456789abcdefABCDEF" for c in stored_hash):
            legacy_hash = hashlib.sha256(pwd_bytes).hexdigest()
            return hmac.compare_digest(legacy_hash.lower(), stored_hash.lower())

        return False

    @classmethod
    def needs_rehash(cls, stored_hash: str) -> bool:
        """
        Determines whether the stored hash is legacy (e.g. unsalted SHA-256)
        and should be upgraded to the current strong algorithm.
        """
        if not stored_hash:
            return True
        # Legacy unsalted SHA-256
        if len(stored_hash) == 64 and all(c in "0123456789abcdefABCDEF" for c in stored_hash):
            return True
        return False

