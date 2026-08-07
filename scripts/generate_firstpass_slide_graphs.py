from pathlib import Path

import matplotlib.pyplot as plt
import japanize_matplotlib  # noqa: F401
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs_active"


def style():
    plt.rcParams["figure.facecolor"] = "#ffffff"
    plt.rcParams["axes.facecolor"] = "#ffffff"
    plt.rcParams["savefig.facecolor"] = "#ffffff"
    plt.rcParams["axes.edgecolor"] = "#d1d5db"
    plt.rcParams["axes.labelcolor"] = "#111827"
    plt.rcParams["xtick.color"] = "#374151"
    plt.rcParams["ytick.color"] = "#374151"
    plt.rcParams["text.color"] = "#111827"
    plt.rcParams["font.size"] = 12
    plt.rcParams["axes.titlelocation"] = "left"


def annotate_barh(ax, bars, texts, dx=0.01):
    for bar, text in zip(bars, texts):
        x = bar.get_width()
        y = bar.get_y() + bar.get_height() / 2
        ax.text(x + dx, y, text, va="center", ha="left", fontsize=11)


def model_selection_graph():
    family_labels = ["forecasting系", "reconstruction系", "one-class系"]
    family_f1 = [0.0, 0.0, 0.667]
    family_notes = [
        "最高でも F1=0.000\nTP=0 / FP=3",
        "最高でも F1=0.000\nTP=0 / FP=2",
        "最高 F1=0.667\nTP=2 / FP=1",
    ]
    family_colors = ["#cbd5e1", "#d9b97d", "#c04d2d"]

    oneclass_labels = [
        "cp10 + IF",
        "cp10 + OCSVM",
        "cp10 + LOF",
        "cu10 + IF",
        "cu10 + OCSVM",
        "cu10 + LOF",
    ]
    oneclass_f1 = [0.0, 0.053, 0.0, 0.667, 0.333, 0.0]
    oneclass_notes = [
        "TP=0 / FP=0",
        "TP=2 / FP=66",
        "TP=0 / FP=0",
        "TP=2 / FP=1",
        "TP=3 / FP=12",
        "TP=0 / FP=0",
    ]
    oneclass_colors = ["#cbd5e1", "#d9b97d", "#cbd5e1", "#c04d2d", "#d9b97d", "#cbd5e1"]

    fig = plt.figure(figsize=(14, 8), dpi=180)
    gs = fig.add_gridspec(2, 1, height_ratios=[1, 1.25], hspace=0.35)

    ax1 = fig.add_subplot(gs[0])
    x = np.arange(len(family_labels))
    bars1 = ax1.bar(x, family_f1, color=family_colors, width=0.56)
    ax1.set_title("第一段階 1/2: 3系統の比較", fontsize=22, fontweight="bold", pad=12)
    ax1.set_ylabel("F1")
    ax1.set_ylim(0, 0.82)
    ax1.set_xticks(x, family_labels)
    ax1.grid(axis="y", color="#e5e7eb")
    for bar, note in zip(bars1, family_notes):
        cx = bar.get_x() + bar.get_width() / 2
        ax1.text(cx, bar.get_height() + 0.03, note, ha="center", va="bottom", fontsize=11)

    ax2 = fig.add_subplot(gs[1])
    y = np.arange(len(oneclass_labels))
    bars2 = ax2.barh(y, oneclass_f1, color=oneclass_colors, height=0.58)
    ax2.set_title("one-class系の比較", fontsize=18, fontweight="bold", pad=10)
    ax2.set_xlabel("F1")
    ax2.set_xlim(0, 0.8)
    ax2.set_yticks(y, oneclass_labels)
    ax2.invert_yaxis()
    ax2.grid(axis="x", color="#e5e7eb")
    annotate_barh(ax2, bars2, oneclass_notes)
    ax2.axvline(0.667, color="#7c2d12", linestyle="--", linewidth=1.5, alpha=0.8)
    fig.savefig(OUT_DIR / "slide_firstpass_model_selection.png", bbox_inches="tight")
    plt.close(fig)


def vectorization_graph():
    labels = [
        "1-1gram TF-IDF",
        "1-2gram TF-IDF",
        "1-3gram TF-IDF",
        "1-2gram count",
        "1-2gram binary",
        "1-2gram tf",
    ]
    f1 = [0.571, 0.667, 0.400, 0.500, 0.500, 0.667]
    recall = [0.667, 0.667, 0.333, 0.667, 0.667, 0.667]
    precision = [0.500, 0.667, 0.500, 0.400, 0.400, 0.667]
    tp = [2, 2, 1, 2, 2, 2]
    fp = [2, 1, 1, 3, 3, 1]
    colors = ["#d9b97d", "#c04d2d", "#d9b97d", "#d9b97d", "#d9b97d", "#9b7340"]

    fig = plt.figure(figsize=(14, 8), dpi=180)
    gs = fig.add_gridspec(2, 1, height_ratios=[1.15, 0.95], hspace=0.33)

    ax1 = fig.add_subplot(gs[0])
    x = np.arange(len(labels))
    width = 0.22
    ax1.bar(x - width, f1, width, label="F1", color="#c04d2d")
    ax1.bar(x, recall, width, label="Recall", color="#d8b77e")
    ax1.bar(x + width, precision, width, label="Precision", color="#8aa1b1")
    ax1.set_title("第一段階 2/2: 入力表現の比較", fontsize=22, fontweight="bold", pad=12)
    ax1.set_ylabel("精度")
    ax1.set_ylim(0, 0.82)
    ax1.set_xticks(x, labels, rotation=10)
    ax1.grid(axis="y", color="#e5e7eb")
    ax1.legend(frameon=False, ncol=3, loc="upper right")
    ax1.axvline(x[1], color="none")

    ax2 = fig.add_subplot(gs[1])
    bars_tp = ax2.bar(x, tp, color=colors, width=0.58, label="TP")
    ax2.bar(x, fp, bottom=tp, color="#cbd5e1", width=0.58, label="FP")
    ax2.set_ylabel("予測陽性系列数")
    ax2.set_xticks(x, labels, rotation=10)
    ax2.grid(axis="y", color="#e5e7eb")
    ax2.legend(frameon=False, ncol=2, loc="upper right")
    for i, (b, t, f) in enumerate(zip(bars_tp, tp, fp)):
        ax2.text(
            b.get_x() + b.get_width() / 2,
            t + f + 0.12,
            f"TP={t}\nFP={f}",
            ha="center",
            va="bottom",
            fontsize=10,
        )

    fig.savefig(OUT_DIR / "slide_firstpass_vectorization.png", bbox_inches="tight")
    plt.close(fig)


def main():
    style()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    model_selection_graph()
    vectorization_graph()


if __name__ == "__main__":
    main()
