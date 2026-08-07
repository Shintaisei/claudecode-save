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


def secondpass_model_compare():
    labels = [
        "IsolationForest",
        "OneClassSVM",
        "LOF",
        "kNN",
        "SGDOneClassSVM",
        "SVD再構成誤差",
    ]
    first_attack_rank = [24, 2, 1, 23, 24, 2]
    top10_attack = [0, 30, 38, 0, 0, 1]
    fp_chunks = [11, 28, 168, 0, 0, 26]
    colors = ["#cbd5e1", "#d8b77e", "#c04d2d", "#cbd5e1", "#cbd5e1", "#9b7340"]

    fig = plt.figure(figsize=(14, 8), dpi=180)
    gs = fig.add_gridspec(2, 1, height_ratios=[1, 1.05], hspace=0.35)

    ax1 = fig.add_subplot(gs[0])
    x = np.arange(len(labels))
    bars1 = ax1.bar(x, top10_attack, color=colors, width=0.62)
    ax1.set_title("第二段階 1/2: 手法比較", fontsize=22, fontweight="bold", pad=12)
    ax1.set_ylabel("top10 に含まれる attack event")
    ax1.set_xticks(x, labels, rotation=10)
    ax1.set_ylim(0, 44)
    ax1.grid(axis="y", color="#e5e7eb")
    for bar, rank in zip(bars1, first_attack_rank):
        cx = bar.get_x() + bar.get_width() / 2
        ax1.text(cx, bar.get_height() + 1.0, f"attack 到達順位\n{rank}", ha="center", va="bottom", fontsize=10)
    ax2 = fig.add_subplot(gs[1])
    width = 0.36
    ax2.bar(x - width / 2, first_attack_rank, width, color="#8aa1b1", label="first attack rank")
    ax2.bar(x + width / 2, fp_chunks, width, color="#d8b77e", label="threshold ベースの FP chunk")
    ax2.set_ylabel("順位 / chunk 数")
    ax2.set_xticks(x, labels, rotation=10)
    ax2.grid(axis="y", color="#e5e7eb")
    ax2.legend(frameon=False, ncol=2, loc="upper right")

    fig.savefig(OUT_DIR / "slide_secondpass_model_compare.png", bbox_inches="tight")
    plt.close(fig)


def secondpass_compression():
    stages = ["attack day 全体", "第一段階後", "第二段階 top10", "第二段階 LOF top3", "第二段階 LOF top1"]
    total_events = [257887, 118495, 1000, 300, 100]
    attack_events = [292, 286, 38, 23, 6]
    normal_events = [257595, 118209, 962, 277, 94]

    fig = plt.figure(figsize=(14, 8), dpi=180)
    gs = fig.add_gridspec(2, 1, height_ratios=[1.1, 0.9], hspace=0.32)

    ax1 = fig.add_subplot(gs[0])
    x = np.arange(len(stages))
    ax1.bar(x, normal_events, color="#d8e5da", width=0.62, label="normal")
    ax1.bar(x, attack_events, bottom=normal_events, color="#c04d2d", width=0.62, label="attack")
    ax1.set_title("第二段階 2/2: 圧縮結果", fontsize=22, fontweight="bold", pad=12)
    ax1.set_ylabel("event 数")
    ax1.set_xticks(x, stages, rotation=0)
    ax1.grid(axis="y", color="#e5e7eb")
    ax1.legend(frameon=False, ncol=2, loc="upper right")
    for i, total in enumerate(total_events):
        ax1.text(i, total + max(total_events) * 0.015, f"{total:,}", ha="center", va="bottom", fontsize=11)

    ax2 = fig.add_subplot(gs[1])
    base = total_events[0]
    reduction = [0, 1 - total_events[1] / base, 1 - total_events[2] / base, 1 - total_events[3] / base, 1 - total_events[4] / base]
    bars = ax2.bar(x, reduction, color=["#cbd5e1", "#d8b77e", "#c04d2d", "#9b7340", "#7c2d12"], width=0.62)
    ax2.set_ylabel("全体からの削減率")
    ax2.set_xticks(x, stages, rotation=0)
    ax2.set_ylim(0, 1.05)
    ax2.grid(axis="y", color="#e5e7eb")
    for bar, val in zip(bars, reduction):
        ax2.text(bar.get_x() + bar.get_width() / 2, val + 0.02, f"{val*100:.1f}%", ha="center", va="bottom", fontsize=11)

    fig.savefig(OUT_DIR / "slide_secondpass_compression.png", bbox_inches="tight")
    plt.close(fig)


def secondpass_reduction_by_model():
    labels = ["LOF", "OneClassSVM", "SVD"]
    attack = [38, 30, 1]
    normal = [962, 970, 999]
    totals = [1000, 1000, 1000]

    fig, ax = plt.subplots(figsize=(13, 7), dpi=180)
    x = np.arange(len(labels))
    ax.bar(x, normal, color="#d8e5da", width=0.62, label="normal")
    ax.bar(x, attack, bottom=normal, color="#c04d2d", width=0.62, label="attack")
    ax.set_title("第二段階: 採用候補ごとの削減結果", fontsize=22, fontweight="bold", pad=12)
    ax.set_ylabel("top10 に残る event 数")
    ax.set_xticks(x, labels)
    ax.set_ylim(0, 1120)
    ax.grid(axis="y", color="#e5e7eb")
    ax.legend(frameon=False, ncol=2, loc="upper right")
    for i, (a, n, t) in enumerate(zip(attack, normal, totals)):
        ax.text(i, t + 28, f"attack={a}\nnormal={n}", ha="center", va="bottom", fontsize=12)

    fig.savefig(OUT_DIR / "slide_secondpass_reduction_by_model.png", bbox_inches="tight")
    plt.close(fig)


def secondpass_ranked_reduction():
    lof_attack = np.array([6, 3, 14, 0, 0, 0, 0, 15, 0, 0])
    lof_normal = np.array([94, 97, 86, 100, 100, 100, 100, 85, 100, 100])
    ocsvm_attack = np.array([0, 1, 0, 0, 0, 17, 1, 11, 0, 0])
    ocsvm_normal = np.array([100, 99, 100, 100, 100, 83, 99, 89, 100, 100])
    x = np.arange(1, 11)

    fig, axes = plt.subplots(1, 2, figsize=(14, 6), dpi=180, sharey=True)
    fig.suptitle("第二段階: 異常スコア順に読んだときの圧縮結果", fontsize=22, fontweight="bold", x=0.06, ha="left")

    for ax, title, attack, normal, color in [
        (axes[0], "LOF", lof_attack, lof_normal, "#c04d2d"),
        (axes[1], "OneClassSVM", ocsvm_attack, ocsvm_normal, "#d8b77e"),
    ]:
        ax.bar(x, normal, color="#d8e5da", width=0.72, label="normal")
        ax.bar(x, attack, bottom=normal, color=color, width=0.72, label="attack")
        ax.set_title(title, fontsize=17, fontweight="bold", pad=10)
        ax.set_xlabel("異常スコア順位 (chunk)")
        ax.set_xticks(x)
        ax.set_ylim(0, 130)
        ax.grid(axis="y", color="#e5e7eb")
        for xi, a, n in zip(x, attack, normal):
            if a > 0:
                ax.text(xi, n + a + 2, f"A={a}", ha="center", va="bottom", fontsize=10, color="#7c2d12")
        cum_attack = attack.cumsum()
        cum_total = (attack + normal).cumsum()
        for xi, ca in zip(x, cum_attack):
            ax.text(
                xi,
                8,
                f"{ca}",
                ha="center",
                va="center",
                fontsize=10,
                color="#1f2a44",
                bbox=dict(boxstyle="round,pad=0.18", facecolor="white", edgecolor="#cbd5e1"),
            )

    axes[0].set_ylabel("各 chunk の event 数")
    from matplotlib.patches import Patch
    legend_handles = [
        Patch(facecolor="#d8e5da", label="normal"),
        Patch(facecolor="#c04d2d", label="attack"),
    ]
    fig.legend(handles=legend_handles, loc="upper center", bbox_to_anchor=(0.5, 0.93), ncol=2, frameon=False)
    fig.text(0.06, 0.08, "各バー下部の数字は、その順位までに保持できた累積 attack event", fontsize=11, color="#4b5563")
    fig.tight_layout(rect=[0, 0.1, 1, 0.9])
    fig.savefig(OUT_DIR / "slide_secondpass_ranked_reduction.png", bbox_inches="tight")
    plt.close(fig)


def main():
    style()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    secondpass_model_compare()
    secondpass_compression()
    secondpass_reduction_by_model()
    secondpass_ranked_reduction()


if __name__ == "__main__":
    main()
