"""Regression tests for importing the data layer without optional dependencies."""

from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class CLIImportTests(unittest.TestCase):
    def tearDown(self) -> None:
        self._clear_app_modules()

    @staticmethod
    def _clear_app_modules() -> None:
        for name in [m for m in list(sys.modules.keys()) if m == "app" or m.startswith("app.")]:
            sys.modules.pop(name, None)

    def test_import_database_without_optional_packages(self) -> None:
        """Importing app.database should succeed even if extras like passlib are missing."""

        self._clear_app_modules()

        fastapi_module: types.ModuleType | None = sys.modules.pop("fastapi", None)
        sys.modules["fastapi"] = None
        try:
            database_module = importlib.import_module("app.database")
            self.assertTrue(hasattr(database_module, "Database"))

            app_module = sys.modules.get("app")
            self.assertIsNotNone(app_module)
            self.assertTrue(hasattr(app_module, "Database"))
        finally:
            sys.modules.pop("fastapi", None)
            if fastapi_module is not None:
                sys.modules["fastapi"] = fastapi_module


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
