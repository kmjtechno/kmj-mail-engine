import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "dependency_inventory", Path(__file__).with_name("dependency-inventory.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def graph():
    return {
        "workspace_members": ["root"],
        "packages": [
            {"id": "root", "name": "stalwart", "version": "1.2.0",
             "license": "AGPL-3.0-only", "source": None},
            {"id": "dep", "name": "example", "version": "1.0.0",
             "license": "MIT OR Apache-2.0",
             "source": "registry+https://example.invalid/private"},
            {"id": "test", "name": "test-only", "version": "1.0.0",
             "license": None, "source": None},
        ],
        "resolve": {"nodes": [
            {"id": "root", "features": ["postgres", "rocks"], "deps": [
                {"pkg": "dep", "dep_kinds": [{"kind": None}]},
                {"pkg": "test", "dep_kinds": [{"kind": "dev"}]},
            ]},
            {"id": "dep", "features": [], "deps": []},
            {"id": "test", "features": [], "deps": []},
        ]},
    }


class InventoryTests(unittest.TestCase):
    def test_only_reachable_non_dev_dependencies_are_reported(self):
        report = MODULE.inventory(graph())
        self.assertEqual(report["package_count"], 2)
        self.assertEqual([p["name"] for p in report["packages"]], ["example", "stalwart"])
        self.assertFalse(report["license_approved"])
        self.assertFalse(report["release_approved"])
        self.assertNotIn("example.invalid", str(report))

    def test_restricted_feature_is_rejected(self):
        data = graph()
        data["resolve"]["nodes"][1]["features"] = ["enterprise"]
        with self.assertRaisesRegex(MODULE.InvalidInventory, "RESTRICTED_FEATURE_PRESENT"):
            MODULE.inventory(data)

    def test_incomplete_graph_is_rejected(self):
        data = graph()
        data["resolve"]["nodes"].pop(1)
        with self.assertRaises(MODULE.InvalidInventory):
            MODULE.inventory(data)

    def test_missing_root_features_are_rejected(self):
        data = graph()
        data["resolve"]["nodes"][0]["features"] = ["rocks"]
        with self.assertRaises(MODULE.InvalidInventory):
            MODULE.inventory(data)

    def test_missing_license_is_reported_not_approved(self):
        data = graph()
        data["packages"][1]["license"] = None
        report = MODULE.inventory(data)
        self.assertEqual(report["missing_license_expression_count"], 1)
        self.assertFalse(report["license_approved"])

    def test_duplicate_package_id_is_rejected(self):
        data = graph()
        data["packages"].append(data["packages"][0])
        with self.assertRaises(MODULE.InvalidInventory):
            MODULE.inventory(data)


if __name__ == "__main__":
    unittest.main()
