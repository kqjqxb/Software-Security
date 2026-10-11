"""Будує залежність мінімальної довжини пароля L від потужності алфавіту A."""
import math
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from auth.anderson import min_length, required_space  # noqa: E402

space = required_space(20, 30, 1e-6)
sizes = range(10, 101)
fig, ax = plt.subplots(figsize=(8, 4.2), dpi=200)
ax.plot(sizes, [math.log(space) / math.log(a) for a in sizes], color="0.55",
        linestyle="--", linewidth=1.5, label="log G / log A")
ax.step(sizes, [min_length(space, a) for a in sizes], where="post",
        color="black", linewidth=2, label="L = ⌈log G / log A⌉")
for alphabet in (26, 62, 95):
    length = min_length(space, alphabet)
    ax.plot(alphabet, length, "o", color="black", markersize=7)
    ax.annotate(f"A = {alphabet}, L = {length}", (alphabet, length),
                textcoords="offset points", xytext=(0, 10),
                ha="right" if alphabet == 95 else "left")
ax.set_xlabel("Потужність алфавіту A")
ax.set_ylabel("Довжина пароля, символів")
ax.set_xlim(10, 100)
ax.set_ylim(5, 13)
ax.grid(color="0.85", linewidth=0.6)
ax.spines[["top", "right"]].set_visible(False)
ax.legend(frameon=False)
fig.tight_layout()
fig.savefig(Path(__file__).with_name("length.png"))
