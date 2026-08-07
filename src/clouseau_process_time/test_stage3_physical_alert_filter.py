import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_clouseau_official_cbc_dense_eval as runner


def create_fixture_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE audit_logs (
                time TEXT,
                source_stream TEXT,
                access TEXT,
                original_table TEXT,
                pid INTEGER,
                ppid INTEGER,
                pname TEXT
            )
            """
        )
        conn.executemany(
            "INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "2018-12-01 19:50:00",
                    "cbc-edr-alerts",
                    "process",
                    "cbc_alerts",
                    100,
                    4,
                    "alert-one.exe",
                ),
                (
                    "2018-12-01 19:50:01",
                    "other",
                    "cbc_alert",
                    "other",
                    101,
                    4,
                    "alert-two.exe",
                ),
                (
                    "2018-12-01 19:50:02",
                    "other",
                    "process",
                    "cbc_alerts",
                    102,
                    4,
                    "alert-three.exe",
                ),
                (
                    "2018-12-01 19:50:03",
                    "cbc-edr",
                    "process",
                    "cbc_events",
                    103,
                    4,
                    "telemetry.exe",
                ),
                (
                    "2018-12-01 19:50:04",
                    "sysmon",
                    "process",
                    "sysmon",
                    104,
                    4,
                    "sysmon.exe",
                ),
            ],
        )
        conn.commit()
    finally:
        conn.close()


class Stage3PhysicalAlertFilterTests(unittest.TestCase):
    def test_filter_removes_every_alert_summary_marker_but_keeps_telemetry(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "fixture.db"
            create_fixture_db(db_path)

            counts = runner.physically_filter_cbc_alert_summary_rows(
                db_path,
                {"base": 1},
            )

            self.assertEqual(counts["cbc_alert_summary_filter_mode"], "physical_adapter_copy_v2")
            self.assertEqual(counts["cbc_alert_summary_rows_hidden_from_stage3_sql"], 3)
            self.assertEqual(counts["cbc_alert_summary_rows_removed"], 3)
            self.assertEqual(counts["post_filter_cbc_alert_summary_rows"], 0)
            self.assertEqual(counts["post_filter_cbc_event_telemetry_rows"], 1)
            self.assertTrue(counts["shared_guarded_sql_tools_preserved"])
            self.assertTrue(counts["shared_guarded_process_tree_tools_preserved"])
            conn = sqlite3.connect(db_path)
            try:
                retained = conn.execute(
                    "SELECT source_stream, original_table FROM audit_logs ORDER BY time"
                ).fetchall()
            finally:
                conn.close()
            self.assertEqual(
                retained,
                [("cbc-edr", "cbc_events"), ("sysmon", "sysmon")],
            )

    def test_cached_adapter_filters_a_copy_and_preserves_unfiltered_cache(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source" / "scenario.db"
            source.parent.mkdir()
            source.touch()
            adapter = root / "runtime" / "scenario.db"
            cache_dir = root / "cache"

            def original_create(_source: Path, destination: Path):
                destination.parent.mkdir(parents=True, exist_ok=True)
                create_fixture_db(destination)
                return {"created": 1}

            with (
                patch.object(runner, "ADAPTER_CACHE_DIR", cache_dir),
                patch.object(runner, "ACTIVE_TIME_SCOPE", None),
                patch.object(runner, "EXCLUDE_CBC_DATABASE", False),
                patch.object(runner, "EXCLUDE_CBC_ALERT_SUMMARY", True),
            ):
                counts = runner.cached_adapter_factory(original_create)(source, adapter)

            unfiltered_cache = cache_dir / "source_scenario_v3_evidence_preserving.db"
            self.assertEqual(runner.count_cbc_alert_summary_rows(unfiltered_cache), 3)
            self.assertEqual(runner.count_cbc_alert_summary_rows(adapter), 0)
            self.assertEqual(counts["cbc_alert_summary_rows_removed"], 3)
            self.assertEqual(counts["post_filter_cbc_event_telemetry_rows"], 1)


if __name__ == "__main__":
    unittest.main()
