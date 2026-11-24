import "./style.css";
import {
  BrowserP2pFiatWallet,
  getLpUrl,
  setLpUrl,
  loadPositions,
  importPrivKeyHex,
} from "./wallet.js";

const $ = (id) => document.getElementById(id);

let appWallet = null;
let lastSpotUsd = 0;

function showToast(msg, ms = 3500) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => el.classList.add("hidden"), ms);
}

function fmtUsd(n) {
  return `$${Number(n || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function renderPositions() {
  const list = Object.values(loadPositions()).sort((a, b) => (b.openedAt || 0) - (a.openedAt || 0));
  const open = list.filter((p) => p.status === "open");
  $("pos-count").textContent = `${open.length} open`;
  const peggedUsd = open.reduce((s, p) => s + Number(p.notionalUsd || 0), 0);
  $("pegged-usd").textContent = fmtUsd(peggedUsd);

  const container = $("positions-list");
  if (list.length === 0) {
    container.innerHTML = `<div class="empty">No positions yet. Board Mutinynet sats and lock USD above.</div>`;
    return peggedUsd;
  }
  container.innerHTML = list
    .map((p) => {
      const isOpen = p.status === "open";
      const estSats =
        isOpen && lastSpotUsd > 0
          ? Math.round((p.notionalUsd / lastSpotUsd) * 1e8)
          : p.userPayoutSats || p.userCollateralSats;
      return `
        <div class="pos-item">
          <div class="pos-top">
            <strong>${fmtUsd(p.notionalUsd)} USD Peg</strong>
            <span class="pill ${isOpen ? "ok" : "muted-pill"}">${p.status}</span>
          </div>
          <div class="pos-meta">
            ID: <code>${p.positionId}</code><br/>
            Open spot: $${Number(p.openSpotUsd).toLocaleString()} · Collateral: ${p.totalCollateralSats.toLocaleString()} sats<br/>
            ${isOpen ? `Est. payout now: <strong>${estSats.toLocaleString()} sats</strong>` : `Closed at $${p.closeSpotUsd} → User: ${p.userPayoutSats} sats`}
          </div>
          ${
            isOpen
              ? `<div class="action-row">
                   <button class="btn secondary small" data-wt="${p.positionId}">Watchtower JSON</button>
                   <button class="btn danger small" data-close="${p.positionId}">Close at Spot</button>
                 </div>`
              : ""
          }
        </div>`;
    })
    .join("");

  container.querySelectorAll("[data-close]").forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.getAttribute("data-close");
      btn.disabled = true;
      btn.textContent = "Closing…";
      try {
        const closed = await appWallet.closePosition(id);
        showToast(`Closed ${id}: received ${closed.userPayoutSats} sats at $${closed.closeSpotUsd}`);
        await refresh();
      } catch (e) {
        showToast(`Close failed: ${e.message}`, 5000);
        btn.disabled = false;
        btn.textContent = "Close at Spot";
      }
    };
  });

  container.querySelectorAll("[data-wt]").forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.getAttribute("data-wt");
      btn.disabled = true;
      try {
        const pkg = await appWallet.exportWatchtowerPackage(id);
        const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: "application/json" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `watchtower-${id}.json`;
        a.click();
        showToast(`Exported ${pkg.unroll_txs.length}-hop watchtower JSON`);
      } catch (e) {
        showToast(`Export failed: ${e.message}`, 5000);
      } finally {
        btn.disabled = false;
      }
    };
  });

  return peggedUsd;
}

async function refresh() {
  if (!appWallet) return;
  try {
    const [addrs, bal] = await Promise.all([appWallet.getAddresses(), appWallet.getBalance()]);
    $("ark-addr").textContent = addrs.arkAddress;
    $("board-addr").textContent = addrs.boardingAddress;
    $("avail-sats").textContent = `${Number(bal.available || 0).toLocaleString()} sats`;
    const boardingConfirmed = Number(bal.boarding?.confirmed || 0);
    const boardingTotal = Number(bal.boarding?.total || 0);
    $("boarding-sats").textContent = `${boardingTotal.toLocaleString()} sats`;
    $("onboard-btn").disabled = boardingConfirmed <= 0;

    let lpOk = false;
    try {
      const health = await appWallet.fetchLpHealth();
      lastSpotUsd = Number(health.spotUsd || 0);
      $("spot-pill").textContent = `BTC $${lastSpotUsd.toLocaleString()}`;
      $("lp-status").textContent = `LP online (${Number(health.arkBalance?.available || 0).toLocaleString()} sats)`;
      $("lp-status").className = "pill ok";
      lpOk = true;
    } catch {
      $("lp-status").textContent = "LP offline";
      $("lp-status").className = "pill err";
    }

    const peggedUsd = renderPositions();
    const availUsd = lastSpotUsd > 0 ? (Number(bal.available || 0) / 1e8) * lastSpotUsd : 0;
    $("total-usd").textContent = fmtUsd(peggedUsd + availUsd);
    $("open-btn").disabled = !lpOk;
  } catch (e) {
    showToast(`Sync error: ${e.message}`, 4500);
  }
}

async function fetchQuoteUi() {
  const usd = Number($("usd-input").value || 0);
  if (usd <= 0) return;
  $("quote-box").textContent = "Fetching live quote from LP…";
  try {
    const q = await appWallet.requestQuote(usd);
    lastSpotUsd = q.spotUsd;
    $("quote-box").innerHTML = `
      Spot: <strong>$${q.spotUsd.toLocaleString()}</strong> · Funding: ${q.fundingRateBpsPerDay} bps/day<br/>
      Your collateral: <strong>${q.userCollateralSats.toLocaleString()} sats</strong> · LP matches: <strong>${q.lpCollateralSats.toLocaleString()} sats</strong><br/>
      Total DLC VTXO: ${q.totalCollateralSats.toLocaleString()} sats (atomic 2-input Arkade tx)
    `;
  } catch (e) {
    $("quote-box").textContent = `Quote error: ${e.message}`;
  }
}

async function boot() {
  $("lp-url-input").value = getLpUrl();
  $("deposit-toggle").onclick = () => $("deposit-panel").classList.toggle("hidden");
  $("settings-btn").onclick = () => $("settings-panel").classList.toggle("hidden");
  $("refresh-btn").onclick = refresh;

  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.onclick = async () => {
      const txt = $(btn.getAttribute("data-copy")).textContent;
      await navigator.clipboard.writeText(txt);
      showToast("Copied to clipboard");
    };
  });

  document.querySelectorAll(".chip").forEach((chip) => {
    chip.onclick = () => {
      document.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      $("usd-input").value = chip.getAttribute("data-usd");
      fetchQuoteUi();
    };
  });

  $("quote-btn").onclick = fetchQuoteUi;
  $("open-btn").onclick = async () => {
    const usd = Number($("usd-input").value || 0);
    if (usd <= 0) return;
    $("open-btn").disabled = true;
    $("open-btn").textContent = "Signing & Opening…";
    try {
      const pos = await appWallet.openPosition(usd);
      showToast(`Locked $${pos.notionalUsd} USD on Arkade (${pos.positionId})`);
      await refresh();
    } catch (e) {
      showToast(`Open failed: ${e.message}`, 5000);
    } finally {
      $("open-btn").disabled = false;
      $("open-btn").textContent = "Lock USD Now";
    }
  };

  $("onboard-btn").onclick = async () => {
    $("onboard-btn").disabled = true;
    $("onboard-btn").textContent = "Joining Arkade batch…";
    try {
      const txid = await appWallet.onboard((ev) => {
        if (ev?.type) $("onboard-btn").textContent = `Batch: ${ev.type}`;
      });
      showToast(`Onboarded! Commitment ${txid.slice(0, 12)}…`);
      await refresh();
    } catch (e) {
      showToast(`Onboard failed: ${e.message}`, 5000);
    } finally {
      $("onboard-btn").textContent = "Onboard L1 → Ark";
    }
  };

  $("save-lp-btn").onclick = () => {
    setLpUrl($("lp-url-input").value);
    showToast("LP URL saved");
    refresh();
  };

  $("reveal-key-btn").onclick = () => {
    const inp = $("privkey-input");
    const hidden = inp.type === "password";
    inp.type = hidden ? "text" : "password";
    $("reveal-key-btn").textContent = hidden ? "Hide" : "Show";
  };

  $("import-key-btn").onclick = async () => {
    const raw = prompt("Paste 64-char hex private key (replaces current browser key):");
    if (!raw) return;
    try {
      importPrivKeyHex(raw);
      showToast("Key imported — reloading wallet");
      location.reload();
    } catch (e) {
      showToast(`Invalid key: ${e.message}`);
    }
  };

  appWallet = await BrowserP2pFiatWallet.create();
  $("privkey-input").value = appWallet.userKey.privHex;
  await refresh();
  await fetchQuoteUi();
}

boot();
