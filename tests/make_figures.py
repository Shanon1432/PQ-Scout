"""Build report figures directly from the results/*.json files, so every
plotted number is traceable to a file produced by a test run.

Run:  python tests/make_figures.py      -> results/figures/*.png
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker

R = "results"
OUT = os.path.join(R, "figures")
os.makedirs(OUT, exist_ok=True)

INK, INK2, MUTED, GRID = "#0b0b0b", "#52514e", "#8a8984", "#e6e5e1"
GOOD, WARN, CRIT = "#0ca30c", "#fab219", "#d03b3b"     # status: correct / safe miss / wrong
S1, S2 = "#2a78d6", "#eb6834"                          # categorical slots 1, 2
plt.rcParams.update({"font.size": 9, "axes.edgecolor": MUTED, "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.titlesize": 10,
                     "axes.titleweight": "bold", "axes.titlecolor": INK})


def clean(ax, xgrid=True):
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.tick_params(axis="y", length=0)
    if xgrid:
        ax.xaxis.grid(True, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)


# --- Figure 1: stress outcomes before vs after the reassembly fix ----------
def fig_stress():
    before = json.load(open(f"{R}/stress_metrics_before_fix.json"))["summary"]
    after = json.load(open(f"{R}/stress_metrics.json"))["summary"]
    conds = ["baseline", "fragmented", "reordered", "duplicated", "lossy", "midsession"]
    segs = [("CORRECT", "Correct", GOOD), ("SAFE_MISS", "Safe miss (no answer)", WARN),
            ("WRONG", "Wrong (confident, incorrect)", CRIT)]
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.9), sharey=True)
    for ax, data, title in ((axes[0], before, "Before fix"), (axes[1], after, "After fix")):
        y = list(range(len(conds)))[::-1]
        for yi, c in zip(y, conds):
            left = 0
            for key, _, col in segs:
                v = data[c][key]
                if v:
                    ax.barh(yi, v - 0.06, left=left + 0.03, height=0.62, color=col)
                    ax.text(left + v / 2, yi, str(v), ha="center", va="center",
                            color="#ffffff" if col != WARN else INK, fontsize=8, fontweight="bold")
                left += v
        ax.set_yticks(y, conds)
        ax.set_xlim(0, 3); ax.set_xticks([0, 1, 2, 3])
        ax.set_title(title, loc="left")
        ax.set_xlabel("cases (of 3)")
        clean(ax)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, _, c in segs]
    fig.legend(handles, [l for _, l, _ in segs], loc="lower center", ncol=3,
               frameon=False, bbox_to_anchor=(0.5, -0.02))
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    fig.savefig(f"{OUT}/fig_stress_before_after.png", dpi=220, bbox_inches="tight")
    plt.close(fig)


# --- Figure 2: HNDL ranking (multiflow capture + the real PQ-hybrid case) ---
def fig_ranking():
    bom = json.load(open(f"{R}/multiflow_cbom.json"))
    rows = []
    for c in bom["components"]:
        p = {x["name"]: x["value"] for x in c.get("properties", [])}
        p["_version"] = c["cryptoProperties"]["protocolProperties"]["version"]
        rows.append((float(p["pqscout:hndlScore"]), p))
    pq = json.load(open(f"{R}/pq_hybrid.json"))["rows"][0]
    items = []
    for score, p in rows:
        port = p.get("pqscout:asset", "").split(":")[-1]
        grp = p.get("pqscout:namedGroup")
        kex = p["pqscout:keyExchange"] + (f" {grp}" if grp and grp != "None" else "")
        items.append((score, f"{p['_version']} · {kex} · port {port}"))
    items.append((pq["score"], "TLS 1.3 · X25519MLKEM768 (hybrid PQ)*"))
    items.sort(key=lambda t: t[0])
    fig, ax = plt.subplots(figsize=(7.2, 3.3))
    for i, (s, label) in enumerate(items):
        ax.barh(i, max(s, 0.6), height=0.62, color=S1)
        ax.text(s + 1.2, i, f"{s:.1f}", va="center", color=INK, fontsize=8, zorder=5,
                bbox=dict(facecolor="white", edgecolor="none", pad=1.0))
    ax.set_yticks(range(len(items)), [l for _, l in items])
    for x, name in ((50, "HIGH ≥ 50"), (70, "CRITICAL ≥ 70")):
        ax.axvline(x, color=MUTED, linewidth=0.9, linestyle=(0, (3, 3)))
        ax.text(x + 0.8, len(items) - 0.45, name, color=INK2, fontsize=7.5, va="bottom")
    ax.set_xlim(0, 100)
    ax.set_xlabel("HNDL exposure score (0–100)")
    clean(ax)
    fig.tight_layout()
    fig.savefig(f"{OUT}/fig_hndl_ranking.png", dpi=220, bbox_inches="tight")
    plt.close(fig)
    return items


# --- Figure 3: what each tool reports, active vs passive -------------------
def fig_nmap():
    rows = json.load(open(f"{R}/nmap_baseline.json"))["rows"]
    labels = {"tls12_ecdhe_rsa": "TLS 1.2 server\n(client: ECDHE-RSA)",
              "tls12_rsa": "TLS 1.2 server\n(client: RSA)",
              "tls13_x25519": "TLS 1.3 server\n(client: X25519)"}
    fig, ax = plt.subplots(figsize=(7.2, 2.7))
    w = 0.34
    for i, r in enumerate(rows):
        n = len(r["nmap_ciphers_found"]); p = 1 if r["pqscout_observed_cipher"] else 0
        ax.bar(i - w / 2 - 0.01, n, w, color=S1)
        ax.bar(i + w / 2 + 0.01, p, w, color=S2)
        ax.text(i - w / 2, n + 0.4, str(n), ha="center", color=INK, fontsize=8)
        ax.text(i + w / 2, p + 0.4, str(p), ha="center", color=INK, fontsize=8)
    ax.set_xticks(range(len(rows)), [labels.get(r["case"], r["case"]) for r in rows])
    ax.set_ylabel("cipher suites reported")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8); ax.set_axisbelow(True)
    ax.legend([plt.Rectangle((0, 0), 1, 1, color=S1), plt.Rectangle((0, 0), 1, 1, color=S2)],
              ["Nmap ssl-enum-ciphers (active: ~1 connection per suite tested)",
               "PQ-Scout (passive: 0 connections, the 1 suite actually used)"],
              frameon=False, loc="lower left", bbox_to_anchor=(0, 1.0), fontsize=7.5)
    ax.set_ylim(0, 23)
    fig.tight_layout()
    fig.savefig(f"{OUT}/fig_nmap_vs_pqscout.png", dpi=220, bbox_inches="tight")
    plt.close(fig)


# --- Figure 5: CIC-IDS2017 public capture (independent data) -------------
def fig_cicids():
    path_after, path_before = f"{R}/cicids2017.json", f"{R}/cicids2017_before_fix.json"
    if not (os.path.exists(path_after) and os.path.exists(path_before)):
        return
    after, before = json.load(open(path_after)), json.load(open(path_before))
    fig, axes = plt.subplots(1, 2, figsize=(7.4, 2.6), gridspec_kw={"width_ratios": [1.15, 1]})

    # (a) TLS version field: agreement with Wireshark, before vs after the fix
    ax = axes[0]
    rows = []
    for label, d in (("Before fix", before), ("After fix", after)):
        x = d["wireshark_cross_check"]
        n = x["agreement"]["version"]["compared"]
        kinds = x.get("disagreement_kind", {})
        blank, diff = kinds.get("version:blank", 0), kinds.get("version:different", 0)
        rows.append((label, n - blank - diff, blank, diff, n))
    segs = [("Agrees with Wireshark", GOOD), ("No answer (safe miss)", WARN),
            ("Different answer", CRIT)]
    for yi, (label, agree, blank, diff, n) in zip((1, 0), rows):
        left = 0
        for v, (_, col) in zip((agree, blank, diff), segs):
            if v:
                ax.barh(yi, v, left=left, height=0.55, color=col)
            left += v
        ax.text(n * 1.01, yi, f"{agree / n:.3%}", va="center", ha="left", color=INK, fontsize=8,
                fontweight="bold")
    ax.set_yticks([1, 0], [r[0] for r in rows])
    ax.set_xlim(0, rows[0][4] * 1.2)
    ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.set_xticks([0, 20000, 40000, 60000])
    ax.set_xlabel(f"connections compared (before {rows[0][4]:,}; after {rows[1][4]:,})")
    ax.set_title("(a) Negotiated TLS version vs Wireshark", loc="left")
    clean(ax)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, c in segs]
    ax.legend(handles, [l for l, _ in segs], loc="upper center", bbox_to_anchor=(0.5, -0.3),
              ncol=3, frameon=False, fontsize=7, handlelength=1, columnspacing=0.8)

    # (b) HNDL band per server asset (after the fix)
    ax = axes[1]
    bands = after["hndl_band_per_asset"]
    order = [("CRITICAL", CRIT), ("HIGH", S2), ("MEDIUM", S1), ("LOW", GOOD), ("REVIEW", MUTED)]
    order = [(b, c) for b, c in order if bands.get(b)]
    y = list(range(len(order)))[::-1]
    for yi, (b, c) in zip(y, order):
        ax.barh(yi, bands[b], height=0.55, color=c)
        ax.text(bands[b] * 1.15 if bands[b] < 1000 else bands[b] * 1.04, yi,
                f"{bands[b]:,}", va="center", ha="left", fontsize=8, color=INK)
    ax.set_xscale("log")
    ax.set_xlim(0.8, max(bands.values()) * 4)
    ax.set_yticks(y, [b for b, _ in order])
    ax.set_xlabel(f"server assets, log scale (n = {after['unique_server_assets']:,})")
    ax.set_title("(b) HNDL band per server asset", loc="left")
    clean(ax)
    fig.tight_layout()
    fig.savefig(f"{OUT}/fig_cicids2017.png", dpi=220, bbox_inches="tight")


if __name__ == "__main__":
    fig_stress(); items = fig_ranking(); fig_nmap(); fig_cicids()
    print("figures written to", OUT)
    for s, l in items[::-1]:
        print(f"  {s:5.1f}  {l}")
