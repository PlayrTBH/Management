"""Tests for password hashing fallbacks when optional dependencies are absent."""

from __future__ import annotations

import importlib
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class PasswordHashingTests(unittest.TestCase):
    def tearDown(self) -> None:
        self._clear_app_modules()

    @staticmethod
    def _clear_app_modules() -> None:
        for name in [m for m in list(sys.modules.keys()) if m == "app" or m.startswith("app.")]:
            sys.modules.pop(name, None)

    def test_hash_and_verify_without_passlib(self) -> None:
        """The fallback PBKDF2 implementation should be used when passlib is missing."""

        self._clear_app_modules()

        sys.modules.pop("passlib", None)
        sys.modules.pop("passlib.context", None)

        with mock.patch.dict(os.environ, {"MANAGEMENT_SESSION_SECRET": "test-secret"}, clear=False):
            with mock.patch.dict(sys.modules, {"fastapi": None, "passlib": None, "passlib.context": None}):
                database = importlib.import_module("app.database")
                hashed = database._hash_password("supersecurepassword")
                self.assertTrue(hashed.startswith("pbkdf2_sha256$"))
                self.assertTrue(database._verify_password("supersecurepassword", hashed))
                self.assertFalse(database._verify_password("incorrect", hashed))

    def test_pbkdf2_hash_verifies_with_passlib_available(self) -> None:
        """PBKDF2 hashes should still be verified when passlib is installed."""

        self._clear_app_modules()
        with mock.patch.dict(os.environ, {"MANAGEMENT_SESSION_SECRET": "test-secret"}, clear=False):
            with mock.patch.dict(sys.modules, {"fastapi": None}, clear=False):
                database = importlib.import_module("app.database")
                hashed = database._hash_password_pbkdf2("anothersecurepassword")
                self.assertTrue(database._verify_password("anothersecurepassword", hashed))
                self.assertFalse(database._verify_password("incorrect", hashed))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
