import argparse
import json
import pickle
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package benign train and attack test sessions into one deep-loglizer dataset."
    )
    parser.add_argument("--train-dir", required=True, help="Directory with session_train.pkl")
    parser.add_argument("--test-dir", required=True, help="Directory with session_test.pkl or attack sessions")
    parser.add_argument("--output-dir", required=True, help="Destination dataset directory")
    parser.add_argument(
        "--test-source",
        default="session_train",
        choices=["session_train", "session_test"],
        help="Which split to use from test-dir",
    )
    return parser.parse_args()


def load_desc(data_dir: Path) -> dict:
    with (data_dir / "data_desc.json").open(encoding="utf-8") as fh:
        return json.load(fh)


def load_pickle(data_dir: Path, name: str) -> dict:
    with (data_dir / name).open("rb") as fh:
        return pickle.load(fh)


def session_anomalies(session_dict: dict) -> int:
    total = 0
    for sample in session_dict.values():
        label = sample["label"]
        if isinstance(label, list):
            total += int(any(x == 1 for x in label))
        else:
            total += int(label == 1)
    return total


def main() -> None:
    args = parse_args()
    train_dir = Path(args.train_dir)
    test_dir = Path(args.test_dir)
    output_dir = Path(args.output_dir)

    benign_desc = load_desc(train_dir)
    attack_desc = load_desc(test_dir)

    session_train = load_pickle(train_dir, "session_train.pkl")
    session_test = load_pickle(test_dir, f"{args.test_source}.pkl")

    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "session_train.pkl").open("wb") as fh:
        pickle.dump(session_train, fh)
    with (output_dir / "session_test.pkl").open("wb") as fh:
        pickle.dump(session_test, fh)

    summary = {
        "train_source": str(train_dir),
        "test_source": str(test_dir),
        "test_source_split": args.test_source,
        "train_sessions": len(session_train),
        "test_sessions": len(session_test),
        "train_session_anomalies": session_anomalies(session_train),
        "test_session_anomalies": session_anomalies(session_test),
        "train_desc": benign_desc,
        "test_desc": attack_desc,
    }
    (output_dir / "data_desc.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(output_dir)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
