import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run single-stage detector loops for ATLAS v2."
    )
    parser.add_argument("--scenario", default="s3", choices=["s3", "s4", "m4", "m5", "m6"])
    parser.add_argument("--run-dir", default="analysis_data/model_runs/single_stage_loop")
    parser.add_argument("--python", default=sys.executable)
    return parser.parse_args()


def run(cmd: list[str]) -> None:
    print(" ".join(cmd))
    subprocess.run(cmd, check=True, cwd=ROOT)


def main() -> int:
    args = parse_args()
    scenario = args.scenario.lower()
    run_dir = ROOT / args.run_dir / scenario
    run_dir.mkdir(parents=True, exist_ok=True)

    cu10_data = f"analysis_data/atlasv2_for_deep-loglizer/exp_benign1_200k_vs_{scenario}_cu10"
    cp10_data = f"analysis_data/atlasv2_for_deep-loglizer/exp_benign1_200k_vs_{scenario}_cp10"
    cp1e100_data = f"analysis_data/atlasv2_for_deep-loglizer/exp_benign1_200k_vs_{scenario}_cp1_e100"

    oneclass_specs = [
        ("iforest_cu10_g12", cu10_data, "iforest", "1", "2"),
        ("iforest_cu10_g13", cu10_data, "iforest", "1", "3"),
        ("lof_cu10_g12", cu10_data, "lof", "1", "2"),
        ("lof_cu10_g13", cu10_data, "lof", "1", "3"),
        ("ocsvm_cu10_g12", cu10_data, "ocsvm", "1", "2"),
        ("ocsvm_cu10_g13", cu10_data, "ocsvm", "1", "3"),
        ("iforest_cp10_g13", cp10_data, "iforest", "1", "3"),
        ("lof_cp10_g13", cp10_data, "lof", "1", "3"),
        ("ocsvm_cp10_g13", cp10_data, "ocsvm", "1", "3"),
    ]
    for name, data_dir, model, ngram_min, ngram_max in oneclass_specs:
        run(
            [
                args.python,
                "scripts/train_atlasv2_oneclass.py",
                "--data-dir",
                data_dir,
                "--output-dir",
                str((run_dir / name).relative_to(ROOT)).replace("\\", "/"),
                "--model",
                model,
                "--ngram-min",
                ngram_min,
                "--ngram-max",
                ngram_max,
            ]
        )

    deep_specs = [
        ("lstm_cu10_sequentials", cu10_data, "lstm", "sequentials"),
        ("lstm_cu10_semantics", cu10_data, "lstm", "semantics"),
        ("transformer_cu10_sequentials", cu10_data, "transformer", "sequentials"),
        ("transformer_cu10_semantics", cu10_data, "transformer", "semantics"),
        ("ae_cu10_sequentials", cu10_data, "ae", "sequentials"),
        ("lstm_cp10_sequentials", cp10_data, "lstm", "sequentials"),
        ("lstm_cp1e100_sequentials", cp1e100_data, "lstm", "sequentials"),
    ]
    for name, data_dir, model, feature_type in deep_specs:
        cmd = [
            args.python,
            "scripts/train_atlasv2_deeploglizer.py",
            "--data-dir",
            data_dir,
            "--output-dir",
            str((run_dir / name).relative_to(ROOT)).replace("\\", "/"),
            "--model",
            model,
            "--feature-type",
            feature_type,
            "--gpu",
            "-1",
        ]
        if model == "ae":
            cmd.extend(["--ae-score-stat", "max"])
        run(cmd)

    local_ngram_output = run_dir / "local_ngram_cu10.json"
    run(
        [
            args.python,
            "scripts/run_atlasv2_local_ngram_baseline.py",
            "--data-dir",
            cu10_data,
            "--split",
            "all",
            "--window-size",
            "5",
            "--topk",
            "3",
            "--output-json",
            str(local_ngram_output.relative_to(ROOT)).replace("\\", "/"),
        ]
    )

    report_cmd = [
        args.python,
        "scripts/report_atlasv2_single_stage.py",
        "--output-md",
        str((run_dir / "comparison.md").relative_to(ROOT)).replace("\\", "/"),
        "--title",
        f"ATLASv2 Single-Stage Detector Comparison ({scenario.upper()})",
        "--local-ngram-json",
        str(local_ngram_output.relative_to(ROOT)).replace("\\", "/"),
    ]
    for name, *_rest in oneclass_specs:
        report_cmd.extend(
            [
                "--result",
                str((run_dir / name / "results.json").relative_to(ROOT)).replace("\\", "/"),
            ]
        )
    for name, *_rest in deep_specs:
        report_cmd.extend(
            [
                "--deep-result",
                str((run_dir / name / "results.json").relative_to(ROOT)).replace("\\", "/"),
            ]
        )
    run(report_cmd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
