/**
 * p2pFiat Web Wallet PWA — UI Controller (`mvp/web/src/main.js`)
 *
 * Orchestrates the mobile-first 3-tier self-custody interface:
 *   1. Stable USD / EUR (DLC positions, live yield ticker, auto-stabilize Receive, auto-liquidate Send)
 *   2. Spending BTC (Arkade VTXOs + Boltz Lightning VHTLC invoices via Unified BIP-21 QR)
 *   3. Bitcoin Vault (L1 P2TR, 0 timelock, bidirectional bridge to Spending)
 *
 * Also manages the Nostr Order Book, P2P Maker Orders, Nostracle reputation & custom oracle
 * settings, keyless Watchtower auto-sync, and 1-string `nsec1...` backup/restore.
 */

import "./style.css";
import QRCode from "qrcode";
import {
  BrowserP2pFiatWallet,
  getLpUrl,
  getNostrRelays,
  setNostrRelays,
  getWatchtowerPubkey,
  setWatchtowerPubkey,
  setDiscoveredWatchtowers,
  getQuorumPreset,
  setQuorumPreset,
  getCustomNostracles,
  addCustomNostracle,
  removeCustomNostracle,
  loadPositions,
  restorePositionsFromNostr,
  restoreFromBackupKey,
  createFreshNostrWallet,
} from "./wallet.js";
import {
  LocalOrderBook,
  NOSTRACLE_POOL,
  QUORUM_PRESETS,
  buildQuorumForPreset,
  pubkeyHexToNpub,
} from "./offerbook.js";
import {
  scanNostracleReputation,
  fetchCuratedNostracleList,
  fetchCuratedWatchtowerList,
} from "./nostracle-client.js";
import {
  fetchNostrProfile,
  publishNostrProfile,
  hasNip07Extension,
  hasStoredAccount,
  loginWithNip07Extension,
  clearAllWalletAuth,
} from "./nostr-account.js";

const $ = (id) => document.getElementById(id);

let appWallet = null;
let activeCurrency = "USD";
let activeSide = "short"; // "short" (Stable USD/EUR) | "long" (2x Long BTC)
let spots = { USD: 0, EUR: 0 };
let lastAvailSats = 0;
let lastVaultSats = 0;
let lastPeggedSats = 0;
let lastPeggedFiat = 0;
let lastArkAddr = "";
let lastVaultAddr = "";
let activeLnInvoice = "";
let activeLnAmountSats = 0;
let receiveContext = "spending"; // "spending" | "vault" | "stable"
let sendSource = "spending"; // "spending" | "vault" | "stable"
let sendIsMax = false;
let stableRecvPollTimer = null;
let stableRecvBaselineSats = 0;
let stableRecvBusy = false;
let vaultDirection = "vault-to-ark"; // "vault-to-ark" | "ark-to-vault"
let vaultIsMax = false;
const orderBook = new LocalOrderBook();
let relaySub = null;
let manualLpPubkey = null;

function curSym(cur = activeCurrency) {
  return String(cur || "USD").toUpperCase() === "EUR" ? "€" : "$";
}

function activePair() {
  return `BTC-${activeCurrency}`;
}

function fmtFiat(n, cur = activeCurrency) {
  return `${curSym(cur)}${Number(n || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function fmtYield(bpsPerDay) {
  const bps = Number(bpsPerDay ?? 3);
  const apr = (bps * 365) / 100;
  const sign = apr >= 0 ? "+" : "";
  return `${sign}${apr.toFixed(1)}% APR`;
}

function fmtInterestFiat(amount, cur = activeCurrency) {
  const val = Number(amount || 0);
  const sign = val >= 0 ? "+" : "-";
  return `${sign}${curSym(cur)}${Math.abs(val).toFixed(5)}`;
}

function computeAccruedInterestUsd(pos, nowMs = Date.now()) {
  if (pos.status !== "open") return Number(pos.accruedInterestUsd || 0);
  const fundingBps = Number(pos.fundingRateBpsPerDay ?? 3);
  const sinceTs = Number(pos.lastRolledAt || pos.openedAt || nowMs / 1000);
  const elapsedSecs = Math.max(0, nowMs / 1000 - sinceTs);
  const carried = Number(pos.carriedInterestUsd || 0);
  return carried + Number(pos.notional ?? pos.notionalUsd ?? 0) * (fundingBps / 10_000) * (elapsedSecs / 86_400);
}

function showToast(msg, ms = 3500) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => el.classList.add("hidden"), ms);
}

function getActiveTradeNotionalFiat() {
  const raw = Number($("usd-input")?.value || 0);
  if (activeSide === "long") {
    const sp = spots[activeCurrency] || spots.USD || 60000;
    return sp > 0 && raw > 0 ? Number(((raw / 1e8) * sp).toFixed(2)) : 0;
  }
  return raw;
}

function getSelectedLp() {
  const amt = getActiveTradeNotionalFiat();
  const offers = orderBook.getOffers({ pair: activePair(), notionalFiat: amt });
  if (offers.length === 0) {
    return { url: getLpUrl(), lpName: "Fallback LP", pubkey: null, fromOrderbook: false };
  }
  const chosen =
    (manualLpPubkey && offers.find((o) => o.pubkey === manualLpPubkey)) || offers[0];
  return {
    url: chosen.endpointUrl || "",
    lpName: chosen.lpName || chosen.pubkey.slice(0, 10),
    pubkey: chosen.pubkey,
    preferNip17: !chosen.endpointUrl,
    fromOrderbook: true,
    offer: chosen,
  };
}

function shortNpub(npub) {
  if (!npub || npub.length < 20) return npub || "—";
  return `${npub.slice(0, 14)}…${npub.slice(-8)}`;
}

let nostracleRep = {};
let nostracleScanBusy = false;
let curatedNostracles = null;
let nostrProfile = null;

function renderNostrAccount() {
  const id = appWallet?.authIdentity || appWallet?.nostrKey;
  if (!id) return;
  const isNip07 = id.mode === "nip07";
  const displayName = (nostrProfile?.name || "").trim();
  const picture =
    nostrProfile?.picture && /^https?:\/\//i.test(nostrProfile.picture)
      ? nostrProfile.picture.trim()
      : "";
  const hasProfile = Boolean(displayName || picture);

  // Top-right header: when signed in, show profile pill (or compact account pill) and hide Login button
  const pill = $("nostr-pill");
  const headerLoginBtn = $("header-nostr-login-btn");
  headerLoginBtn?.classList.add("hidden");
  if (hasProfile || isNip07) {
    pill.textContent = "";
    if (picture) {
      const img = document.createElement("img");
      img.src = picture;
      img.alt = displayName || "Profile";
      img.onerror = () => img.remove();
      pill.appendChild(img);
    }
    const span = document.createElement("span");
    span.textContent = displayName || `⚡ ${id.npub.slice(0, 10)}…`;
    pill.appendChild(span);
    pill.classList.remove("hidden");
  } else {
    pill.classList.add("hidden");
  }

  // Auth mode badge in Settings
  const modeBadge = $("auth-mode-badge");
  if (modeBadge) {
    modeBadge.innerHTML = isNip07
      ? `⚡ <strong>Signed in via Nostr Extension</strong> (<code>${id.npub.slice(0, 14)}…</code>) — Arkade &amp; L1 Vault seed synced encrypted via NIP-44`
      : `🔑 <strong>Signed in with Local Backup Key</strong> (<code>${id.npub.slice(0, 14)}…</code>)`;
  }

  // Unified Wallet Backup Key (nsec in local mode, emergency offline walletSeed in NIP-07 mode)
  $("backup-key-label").textContent = isNip07
    ? "Emergency Offline Wallet Seed (already synced encrypted via NIP-44 to your Nostr Extension)"
    : "Wallet Backup Key (single secret string — restores your entire wallet)";
  $("backup-key-input").value = isNip07 ? id.walletSeedHex : id.nsec;
  $("legacy-key-warning").classList.toggle("hidden", !appWallet.isLegacySeparateKey);

  // Advanced → Nostr section
  $("nostr-npub").textContent = id.npub;
  const primalLink = $("nostr-primal-link");
  if (primalLink) primalLink.href = `https://primal.net/p/${id.npub}`;
  if (displayName && !$("nostr-name-input").value) {
    $("nostr-name-input").value = displayName;
  }
  if (picture && !$("nostr-pic-input").value) {
    $("nostr-pic-input").value = picture;
  }

  const headerEl = $("nostr-profile-header");
  if (hasProfile) {
    headerEl.classList.remove("hidden");
    $("nostr-display-name").textContent = displayName || "Profile";
    $("nostr-nip05").textContent = nostrProfile?.nip05 || "";
    const avatarEl = $("nostr-avatar");
    avatarEl.textContent = "";
    if (picture) {
      const img = document.createElement("img");
      img.src = picture;
      img.alt = displayName || "Profile avatar";
      img.onerror = () => {
        avatarEl.textContent = (displayName || "P").slice(0, 1).toUpperCase();
      };
      avatarEl.appendChild(img);
    } else {
      avatarEl.textContent = displayName.slice(0, 1).toUpperCase();
    }
  } else {
    headerEl.classList.add("hidden");
  }
}

async function refreshNostrProfile() {
  const id = appWallet?.authIdentity || appWallet?.nostrKey;
  if (!id) return;
  nostrProfile = await fetchNostrProfile(id.pubHex, getNostrRelays()).catch(() => null);
  renderNostrAccount();
}

function getEffectiveNostraclePool() {
  const custom = getCustomNostracles();
  const base = curatedNostracles && curatedNostracles.length > 0 ? curatedNostracles : NOSTRACLE_POOL;
  const seen = new Set();
  const merged = [];
  for (const o of [...custom, ...base]) {
    if (!o?.pubkey || seen.has(o.pubkey)) continue;
    seen.add(o.pubkey);
    merged.push(o);
  }
  return merged;
}

async function refreshNostracleReputation() {
  if (nostracleScanBusy) return;
  nostracleScanBusy = true;
  try {
    const relays = getNostrRelays();
    const [liveDir, liveWts] = await Promise.all([
      fetchCuratedNostracleList(relays).catch(() => null),
      fetchCuratedWatchtowerList(relays).catch(() => null),
    ]);
    if (liveDir && liveDir.length > 0) curatedNostracles = liveDir;
    if (liveWts && liveWts.length > 0) {
      setDiscoveredWatchtowers(liveWts);
      if ($("wt-pubkey-input") && !$("wt-pubkey-input").matches(":focus")) {
        $("wt-pubkey-input").value = getWatchtowerPubkey();
      }
    }
    const pool = getEffectiveNostraclePool();
    nostracleRep = await scanNostracleReputation(
      pool.map((o) => o.pubkey),
      relays
    );
    renderNostracles();
  } finally {
    nostracleScanBusy = false;
  }
}

function fmtAge(rep) {
  if (!rep || rep.ageDays === null) return "no relay history";
  if (rep.ageDays === 0) return "<1d online";
  return `${rep.ageDays}d history`;
}

function renderNostracles() {
  const presetId = getQuorumPreset();
  const baseQ = buildQuorumForPreset(presetId);
  const pool = getEffectiveNostraclePool();
  const q = { ...baseQ, oracles: pool.slice(0, Math.min(baseQ.total, pool.length)) };
  const meta = QUORUM_PRESETS[presetId] || QUORUM_PRESETS["3-of-5"];
  const sel = $("quorum-select");
  if (sel) sel.value = presetId;
  const note = $("quorum-note");
  const onlineInQuorum = q.oracles.filter((o) => nostracleRep[o.pubkey]?.online).length;
  const scanned = Object.keys(nostracleRep).length > 0;

  if (note) {
    const cheapestSum = [...q.oracles]
      .map((o) => nostracleRep[o.pubkey]?.advertisedFeeSats ?? o.feeSats ?? 0)
      .sort((a, b) => a - b)
      .slice(0, q.threshold)
      .reduce((s, f) => s + f, 0);
    const liveSummary = scanned
      ? ` · Live on relays: ${onlineInQuorum}/${q.oracles.length}` +
        (onlineInQuorum < q.threshold ? " (⚠ fewer online than threshold)" : "")
      : " · Scanning relay reputation…";
    note.textContent = `${meta.note} Cheapest ${q.threshold} dispute zaps ≈ ${cheapestSum} sats${liveSummary}`;
  }

  const box = $("nostracles-box");
  if (!box) return;
  box.innerHTML = q.oracles
    .map((o) => {
      const npub = o.npub || (o.pubkey ? pubkeyHexToNpub(o.pubkey) : "");
      const rep = nostracleRep[o.pubkey];
      const fee = rep?.advertisedFeeSats ?? o.feeSats ?? 0;
      const statusHtml = rep
        ? rep.online
          ? `<span class="accent-green">● Online</span> · ${fmtAge(rep)} · ${rep.announcements} ann / ${rep.attestations} att / ${rep.socialPosts} notes · ${fee}s`
          : `<span class="muted">○ Offline/Test</span> · ${fmtAge(rep)} · ${fee}s`
        : `<span class="muted">Checking relays… · ${fee}s</span>`;
      return `
        <div class="nostracle-item">
          <div class="copy-row" style="justify-content:space-between">
            <span style="font-size:0.8rem;font-weight:600">${o.name}${o.custom ? ` <span class="pill ok" style="font-size:0.65rem;padding:1px 6px">Custom</span>` : ""} <span class="muted" style="font-family:monospace;font-weight:400" title="${npub}">${shortNpub(npub)}</span></span>
            <span class="mini-actions" style="margin-top:0">
              <button class="btn small secondary" data-copy-text="${npub}" style="flex:0 0 auto">Copy</button>
              <a class="btn small secondary" href="https://primal.net/p/${npub}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;flex:0 0 auto">Feed ↗</a>
              ${o.custom ? `<button class="close-x" data-rm-nostracle="${o.pubkey}" title="Remove custom Nostracle" aria-label="Remove">✕</button>` : ""}
            </span>
          </div>
          <div class="nostracle-rep">${statusHtml}</div>
        </div>`;
    })
    .join("");
  box.querySelectorAll("[data-copy-text]").forEach((btn) => {
    btn.onclick = async () => {
      const txt = btn.getAttribute("data-copy-text");
      await navigator.clipboard.writeText(txt);
      showToast(`Copied ${shortNpub(txt)}`);
    };
  });
  box.querySelectorAll("[data-rm-nostracle]").forEach((btn) => {
    btn.onclick = () => {
      removeCustomNostracle(btn.getAttribute("data-rm-nostracle"));
      renderNostracles();
      showToast("Removed custom Nostracle");
    };
  });
}

function renderOrderBook() {
  const amt = getActiveTradeNotionalFiat();
  const pair = activePair();
  const sym = curSym();
  const offers = orderBook.getOffers({ pair, notionalFiat: amt });
  const oracle = orderBook.getOrderbookPrice({ pair });
  const selected = getSelectedLp();
  renderNostracles(selected.offer?.oracleQuorum);

  if (oracle.medianMidUsd) {
    const pofTag = oracle.isSybilResistant
      ? `<span class="pill ok">✓ PoF-Weighted (${oracle.verifiedLpCount} LPs · ${oracle.totalVerifiedSats.toLocaleString()} sats)</span>`
      : `<span class="muted">(${oracle.lpCount} LP${oracle.lpCount === 1 ? "" : "s"} · verifying PoF…)</span>`;
    $("ob-oracle-bar").innerHTML = `
      ${pair} Price Oracle: <strong>${sym}${oracle.medianMidUsd.toLocaleString()}</strong> ${pofTag}
    `;
  } else {
    $("ob-oracle-bar").innerHTML = `
      ${pair} Price Oracle: <strong>—</strong> <span class="muted">(waiting for signed LP offers; using fallback LP)</span>
    `;
  }

  $("ob-auto-btn").textContent = manualLpPubkey ? "Switch to Auto Best" : "Auto Best ✓";

  const obToggle = $("ob-toggle-btn");
  if (obToggle) {
    const isOpen = !$("orderbook-drawer")?.classList.contains("hidden");
    const bestLabel = offers[0]?.lpName || selected.lpName;
    const countTxt = offers.length > 0 ? `${offers.length} offer${offers.length === 1 ? "" : "s"} · Best: ${bestLabel}` : "fallback LP";
    obToggle.textContent = isOpen ? `Hide Order Book (${countTxt}) ▴` : `Compare Offers (${countTxt}) ▾`;
  }

  const container = $("orderbook-list");
  if (offers.length === 0) {
    container.innerHTML = `<div class="empty">No active Nostr <code>kind:38384</code> ${pair} offers yet — fallback LP URL is used.</div>`;
    return;
  }

  container.innerHTML = offers
    .map((o, idx) => {
      const isBest = idx === 0 && o.canFill;
      const isSelected = selected.pubkey === o.pubkey;
      const pofBadge = o.pofVerified
        ? o.verifiedLiquiditySats > 0
          ? `<span class="pill ok">✓ PoF ${o.verifiedLiquiditySats.toLocaleString()} sats</span>`
          : `<span class="pill err">PoF 0 sats</span>`
        : `<span class="pill muted-pill">Checking PoF…</span>`;
      const isP2p = o.makerType === "p2p";
      const isMine = appWallet?.nostrKey?.pubHex && o.pubkey === appWallet.nostrKey.pubHex;
      const transportPill = isP2p
        ? `<span class="pill best">P2P Peer</span>`
        : !o.endpointUrl
        ? `<span class="pill ok">NIP-17 P2P</span>`
        : o.transports?.includes("nostr-nip17")
        ? `<span class="pill muted-pill">HTTP+NIP17</span>`
        : "";
      const takerSideLabel =
        o.takerSide === "long" ? "🚀 2× Long BTC" : `🛡 Stable ${o.currency || activeCurrency}`;
      const entryPrice =
        activeSide === "long"
          ? Number(o.askPrice ?? o.askUsd)
          : Number(o.bidPrice ?? o.bidUsd);
      const shownRate =
        activeSide === "long" ? -Number(o.fundingRateBpsPerDay || 0) : Number(o.fundingRateBpsPerDay || 0);
      const rateLabel = activeSide === "long" ? "Funding" : "Yield";
      const termDays = Math.max(1, Math.round(Number(o.termSecs || 86_400) / 86_400));
      const termTxt = `${termDays}d`;
      const metaLine = isP2p
        ? `Exact ${fmtFiat(o.exactNotional ?? o.minNotionalUsd, o.currency)} · Term <strong>${termTxt}</strong> · Match → <strong>${takerSideLabel}</strong> · ${fmtYield(-Number(o.fundingRateBpsPerDay || 0))}`
        : `Entry <strong>${sym}${entryPrice.toLocaleString()}</strong> · Term <strong>${termTxt}</strong> · <span class="${shownRate >= 0 ? "accent-green" : "accent-red"}">${rateLabel} ${fmtYield(shownRate)}</span> · ${o.pofVerified ? `Max VTXO ${Number(o.maxVtxoSats).toLocaleString()} sats` : `Claimed ${Number(o.availableLiquiditySats).toLocaleString()} sats`}`;
      return `
        <div class="ob-row ${isSelected ? "selected" : ""}" data-pubkey="${o.pubkey}">
          <div class="ob-row-top">
            <span><strong>${o.lpName || "LP"}</strong>${isMine ? ` <span class="muted">(You)</span>` : ""} <code>${o.pubkey.slice(0, 8)}…</code></span>
            <span class="ob-pills">
              ${transportPill}
              ${pofBadge}
              ${isBest && !isP2p ? `<span class="pill best">BEST</span>` : ""}
              ${isSelected ? `<span class="pill ok">ACTIVE</span>` : ""}
            </span>
          </div>
          <div class="ob-row-meta">${metaLine}</div>
        </div>`;
    })
    .join("");

  container.querySelectorAll("[data-pubkey]").forEach((row) => {
    row.onclick = () => {
      const pk = row.getAttribute("data-pubkey");
      const clicked = offers.find((o) => o.pubkey === pk);
      if (clicked?.makerType === "p2p" && appWallet?.nostrKey?.pubHex === pk) {
        showToast("This is your own live P2P order — waiting for a peer to match it");
        return;
      }
      manualLpPubkey = pk;
      if (clicked?.makerType === "p2p") {
        activeSide = clicked.takerSide === "long" ? "long" : "short";
        if (clicked.exactNotional) $("usd-input").value = clicked.exactNotional;
        applyCurrencyUi();
      }
      renderOrderBook();
      refresh();
      fetchQuoteUi();
    };
  });
}

function renderMyP2pOrderBanner() {
  const el = $("my-p2p-order-banner");
  if (!el) return;
  const ord = appWallet?.activeP2pOrder;
  if (!ord) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  const sideTxt = ord.makerSide === "long" ? "🚀 2× Long BTC" : `🛡 Stable ${ord.currency}`;
  el.innerHTML = `
    <span>🟢 <strong>Your P2P Order is Live:</strong> ${fmtFiat(ord.notional, ord.currency)} ${sideTxt} (${fmtYield(ord.makerFundingBps)} · keep tab open)</span>
    <button id="cancel-p2p-btn" class="btn small danger" style="flex:0 0 auto">Cancel</button>
  `;
  el.classList.remove("hidden");
  $("cancel-p2p-btn").onclick = async () => {
    $("cancel-p2p-btn").disabled = true;
    try {
      await appWallet.cancelP2pOrder();
      renderMyP2pOrderBanner();
      showToast("P2P order cancelled");
    } catch (e) {
      showToast(`Cancel failed: ${e.message}`, 4000);
    }
  };
}

let pofBusy = false;
async function verifyOrderBookPof(force = false) {
  if (!appWallet || pofBusy) return;
  pofBusy = true;
  try {
    const updated = await appWallet.verifyOrderBook(orderBook, { force });
    if (updated > 0) {
      renderOrderBook();
    }
  } finally {
    pofBusy = false;
  }
}

function startOrderBookSubscription() {
  relaySub?.close();
  const relays = getNostrRelays();
  relaySub = orderBook.subscribeRelays(relays, {
    onUpdate: () => {
      renderOrderBook();
      verifyOrderBookPof(false);
      refresh();
    },
    onStatus: (statuses) => {
      const values = Object.values(statuses);
      const live = values.filter((s) => s === "live" || s === "connected").length;
      const pill = $("relay-status");
      pill.textContent = `Relays: ${live}/${values.length}`;
      pill.className = `pill ${live > 0 ? "ok" : "muted-pill"}`;
    },
  });
}

function estimatePositionSats(pos, spotPrice, interestFiat) {
  const total = Number(pos.totalCollateralSats || 0);
  const notional = Number(pos.notional ?? pos.notionalUsd ?? 0);
  if (!spotPrice || spotPrice <= 0) return pos.userPayoutSats || pos.userCollateralSats || 0;
  const dust = 330;
  if (pos.side === "long") {
    const lpFiat = Math.max(0.01, notional - interestFiat);
    const lpRaw = Math.round((lpFiat / spotPrice) * 1e8);
    const lpClamped = Math.min(Math.max(lpRaw, dust), Math.max(dust, total - dust));
    return Math.max(0, total - lpClamped);
  }
  const userRaw = Math.round((Math.max(0.01, notional + interestFiat) / spotPrice) * 1e8);
  return Math.min(Math.max(userRaw, dust), Math.max(dust, total - dust));
}

function tickInterest() {
  const list = Object.values(loadPositions());
  const open = list.filter((p) => p.status === "open");
  let totalInterestActive = 0;
  let peggedActive = 0;
  let peggedWeightedAprSum = 0;
  let peggedSatsTotal = 0;
  let longEquityActive = 0;
  let longCostActive = 0;
  let longSatsTotal = 0;
  let longInitSatsTotal = 0;
  let longWeightedEntrySum = 0;
  let longWeightedLiqSum = 0;
  let longCount = 0;
  const nowMs = Date.now();
  const activeSpot = spots[activeCurrency] || spots.USD || 0;

  for (const p of open) {
    const pCur = (p.currency || "USD").toUpperCase();
    const pNotional = Number(p.notional ?? p.notionalUsd ?? 0);
    const interest = computeAccruedInterestUsd(p, nowMs);
    const pSpot = spots[pCur] || p.openSpotPrice || p.openSpotUsd || activeSpot;
    const estSats = estimatePositionSats(p, pSpot, interest);

    const fx =
      pCur === activeCurrency
        ? 1
        : spots[activeCurrency] && spots[pCur]
        ? spots[activeCurrency] / spots[pCur]
        : 1;

    if (p.side === "long") {
      const valFiat = pSpot > 0 ? (estSats / 1e8) * pSpot : pNotional;
      const initSats = Number(p.userCollateralSats || 0);
      const entryP = Number(p.openSpotPrice ?? p.openSpotUsd ?? pSpot) * fx;
      const liqP = Number(p.liquidationPrice || Math.round((p.openSpotPrice ?? p.openSpotUsd ?? pSpot) * 0.5)) * fx;
      longCount++;
      longSatsTotal += estSats;
      longInitSatsTotal += initSats;
      longEquityActive += valFiat * fx;
      longCostActive += pNotional * fx;
      longWeightedEntrySum += entryP * Math.max(1, initSats);
      longWeightedLiqSum += liqP * Math.max(1, initSats);
      const pnlFiat = valFiat - pNotional;
      const pnlSats = estSats - initSats;
      const pnlPct = pNotional > 0 ? (pnlFiat / pNotional) * 100 : 0;
      const el = document.querySelector(`[data-interest-pos="${p.positionId}"]`);
      if (el) {
        const sign = pnlFiat >= 0 ? "+" : "-";
        const sSign = pnlSats >= 0 ? "+" : "-";
        el.textContent = `${sign}${curSym(pCur)}${Math.abs(pnlFiat).toFixed(2)} (${sign}${Math.abs(pnlPct).toFixed(1)}%) · ${sSign}${Math.abs(pnlSats).toLocaleString()} sats · Est. payout: ${estSats.toLocaleString()} sats`;
        el.className = pnlFiat >= 0 ? "accent-green" : "accent-red";
      }
    } else {
      const posFiatActive = pNotional * fx;
      const posApr = (Number(p.fundingRateBpsPerDay ?? 3) * 365) / 100;
      peggedActive += posFiatActive;
      peggedWeightedAprSum += posFiatActive * posApr;
      peggedSatsTotal += estSats;
      totalInterestActive += interest * fx;
      const el = document.querySelector(`[data-interest-pos="${p.positionId}"]`);
      if (el) {
        el.textContent = `${fmtInterestFiat(interest, pCur)} · Est. payout: ${estSats.toLocaleString()} sats`;
        el.className = interest >= 0 ? "accent-green" : "accent-red";
      }
    }
  }

  lastPeggedSats = peggedSatsTotal;
  lastPeggedFiat = peggedActive + totalInterestActive;
  $("pegged-usd").textContent = fmtFiat(peggedActive, activeCurrency);
  if ($("pegged-sats")) $("pegged-sats").textContent = `≈ ${peggedSatsTotal.toLocaleString()} sats`;
  const sub = $("accrued-interest-total");
  if (sub) {
    const weightedApr = peggedActive > 0 ? peggedWeightedAprSum / peggedActive : 0;
    const aprSign = weightedApr >= 0 ? "+" : "";
    const aprPart = peggedActive > 0 ? ` · ${aprSign}${weightedApr.toFixed(1)}% APR` : "";
    sub.textContent = `${fmtInterestFiat(totalInterestActive, activeCurrency)} yield${aprPart}`;
    sub.className = `interest-sub ${totalInterestActive >= 0 ? "accent-green" : "accent-red"}`;
  }
  const spendingFiat = activeSpot > 0 ? (lastAvailSats / 1e8) * activeSpot : 0;
  const vaultFiat = activeSpot > 0 ? (lastVaultSats / 1e8) * activeSpot : 0;
  if ($("avail-fiat")) $("avail-fiat").textContent = `≈ ${fmtFiat(spendingFiat, activeCurrency)}`;
  if ($("vault-fiat")) $("vault-fiat").textContent = `≈ ${fmtFiat(vaultFiat, activeCurrency)}`;
  const longBox = $("long-tier-box");
  if (longBox) {
    longBox.classList.toggle("hidden", longCount === 0);
    if (longCount > 0) {
      const longPnl = longEquityActive - longCostActive;
      const longPnlSats = longSatsTotal - longInitSatsTotal;
      const longPnlPct = longCostActive > 0 ? (longPnl / longCostActive) * 100 : 0;
      const sign = longPnl >= 0 ? "+" : "-";
      const sSign = longPnlSats >= 0 ? "+" : "-";
      const sym = curSym();
      if ($("long-sats")) $("long-sats").textContent = `${longSatsTotal.toLocaleString()} sats`;
      if ($("long-fiat")) $("long-fiat").textContent = `≈ ${fmtFiat(longEquityActive, activeCurrency)}`;
      const lr = $("long-return");
      if (lr) {
        lr.textContent = `${sign}${sym}${Math.abs(longPnl).toFixed(2)} (${sign}${Math.abs(longPnlPct).toFixed(1)}%) · ${sSign}${Math.abs(longPnlSats).toLocaleString()} sats`;
        lr.className = `interest-sub ${longPnl >= 0 ? "accent-green" : "accent-red"}`;
      }
      // Dynamic diagonal 2x payoff SVG:
      // Below entry -> X runs Liq (0.5x) to 1.25x Entry (extra breathing room between Liq and Entry).
      // Above entry -> X scales up smoothly to at most 2x Entry so the green line extends past Now.
      const denom = Math.max(1, longInitSatsTotal);
      const avgEntry = Math.round(longWeightedEntrySum / denom);
      const avgLiq = Math.round(longWeightedLiqSum / denom);
      const nowSpot = Math.round(activeSpot || avgEntry);
      const maxP =
        nowSpot <= avgEntry
          ? Math.round(avgEntry * 1.25)
          : Math.round(Math.max(avgEntry * 1.25, Math.min(avgEntry * 2, nowSpot * 1.15)));
      const span = Math.max(1, maxP - avgLiq);
      const entryRatio = Math.min(0.9, Math.max(0.1, (avgEntry - avgLiq) / span));
      const nowRatio = Math.min(1, Math.max(0, (nowSpot - avgLiq) / span));
      const x0 = 8;
      const x1 = 312;
      const yBottom = 60;
      const yTop = 6;
      const entryX = (x0 + entryRatio * (x1 - x0)).toFixed(1);
      const entryY = (yBottom - entryRatio * (yBottom - yTop)).toFixed(1);
      const nowX = (x0 + nowRatio * (x1 - x0)).toFixed(1);
      const nowY = (yBottom - nowRatio * (yBottom - yTop)).toFixed(1);
      const isUp = nowSpot >= avgEntry;
      const strokeCol = isUp ? "#22c55e" : "#ef4444";
      const haloCol = isUp ? "rgba(34,197,94,0.28)" : "rgba(239,68,68,0.28)";

      $("long-loss-poly")?.setAttribute("points", `${x0},${yBottom} ${entryX},${entryY} ${entryX},${yBottom}`);
      $("long-gain-poly")?.setAttribute("points", `${entryX},${entryY} ${x1},${yTop} ${x1},${yBottom} ${entryX},${yBottom}`);
      $("long-be-line")?.setAttribute("y1", entryY);
      $("long-be-line")?.setAttribute("y2", entryY);
      $("long-entry-guide")?.setAttribute("x1", entryX);
      $("long-entry-guide")?.setAttribute("x2", entryX);
      $("long-loss-line")?.setAttribute("x2", entryX);
      $("long-loss-line")?.setAttribute("y2", entryY);
      $("long-gain-line")?.setAttribute("x1", entryX);
      $("long-gain-line")?.setAttribute("y1", entryY);
      $("long-entry-dot")?.setAttribute("cx", entryX);
      $("long-entry-dot")?.setAttribute("cy", entryY);

      const dot = $("long-now-dot");
      const halo = $("long-now-halo");
      const guide = $("long-now-guide");
      if (dot) {
        dot.setAttribute("cx", nowX);
        dot.setAttribute("cy", nowY);
        dot.setAttribute("fill", strokeCol);
      }
      if (halo) {
        halo.setAttribute("cx", nowX);
        halo.setAttribute("cy", nowY);
        halo.setAttribute("fill", haloCol);
      }
      if (guide) {
        guide.setAttribute("x1", nowX);
        guide.setAttribute("y1", String(yTop));
        guide.setAttribute("x2", nowX);
        guide.setAttribute("y2", String(yBottom));
        guide.setAttribute("stroke", strokeCol);
      }
      if ($("long-lbl-liq")) $("long-lbl-liq").textContent = `Liq ${sym}${avgLiq.toLocaleString()}`;
      const midLbl = $("long-lbl-mid");
      const rightLbl = $("long-lbl-right");
      if (midLbl && rightLbl) {
        if (isUp) {
          midLbl.textContent = `Entry ${sym}${avgEntry.toLocaleString()}`;
          midLbl.className = "";
          midLbl.style.color = "var(--accent)";
          midLbl.style.fontWeight = "600";
          rightLbl.textContent = `Now ${sym}${nowSpot.toLocaleString()}`;
          rightLbl.className = "accent-green";
          rightLbl.style.color = "";
          rightLbl.style.fontWeight = "700";
        } else {
          midLbl.textContent = `Now ${sym}${nowSpot.toLocaleString()}`;
          midLbl.className = "accent-red";
          midLbl.style.color = "";
          midLbl.style.fontWeight = "700";
          rightLbl.textContent = `Entry ${sym}${avgEntry.toLocaleString()}`;
          rightLbl.className = "";
          rightLbl.style.color = "var(--accent)";
          rightLbl.style.fontWeight = "600";
        }
      }
    }
  }
  $("total-usd").textContent = fmtFiat(
    peggedActive + totalInterestActive + longEquityActive + spendingFiat + vaultFiat,
    activeCurrency
  );
}

function fmtTimeLeft(secs) {
  if (secs <= 0) return "Expired";
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function getRollReason(pos, nowSecs) {
  const isLong = pos.side === "long";
  const termSecs = Number(pos.termSecs || 86_400);
  const startTs = Number(pos.lastRolledAt || pos.openedAt || nowSecs);
  const secsLeft = startTs + termSecs - nowSecs;
  const posYield = Number(pos.fundingRateBpsPerDay ?? (isLong ? -3 : 3));

  // Compare with current LP offer (or best live offer) in the orderbook.
  // Orderbook `fundingRateBpsPerDay` is quoted for Stable Short; for 2x Long the user pays `-rate`.
  const posCur = (pos.currency || "USD").toUpperCase();
  const liveOffers = orderBook.getOffers({
    pair: `BTC-${posCur}`,
    notionalFiat: Number(pos.notional ?? pos.notionalUsd ?? 0),
  });
  const sameLp = liveOffers.find((o) => o.pubkey === (pos.lpPubkey || pos.lpPubHex));
  const bestOffer = liveOffers[0];
  const rawRef = sameLp ? sameLp.fundingRateBpsPerDay : bestOffer?.fundingRateBpsPerDay;
  const refYield = Number.isFinite(rawRef) ? (isLong ? -Math.abs(rawRef) : rawRef) : NaN;
  const fmtSignedApr = (bpsPerDay) => {
    const apr = (bpsPerDay * 365) / 100;
    return `${apr >= 0 ? "+" : ""}${apr.toFixed(1)}%`;
  };

  if (secsLeft <= 0) {
    return {
      urgent: true,
      good: false,
      text: isLong
        ? "Term expired — Roll now to keep your 2× Long BTC active"
        : `Term expired — Roll now to keep your ${posCur} peg active`,
    };
  }
  if (secsLeft < 6 * 3600) {
    return {
      urgent: true,
      good: false,
      text: `Expiry approaching (${fmtTimeLeft(secsLeft)} left) — Roll to extend 24h`,
    };
  }
  if (Number.isFinite(refYield) && refYield > posYield + 0.1) {
    return {
      urgent: false,
      good: true,
      text: isLong
        ? `↓ Lower funding available (${fmtSignedApr(refYield)} vs ${fmtSignedApr(posYield)} APR) — Roll to save`
        : `↑ Higher yield available (${fmtSignedApr(refYield)} vs ${fmtSignedApr(posYield)} APR) — Roll to upgrade`,
    };
  }
  return {
    urgent: false,
    good: false,
    text: isLong
      ? `Expires in ${fmtTimeLeft(secsLeft)} · Roll resets margin & extends 24h`
      : `Expires in ${fmtTimeLeft(secsLeft)} · Roll re-centers peg & extends 24h`,
  };
}

function renderPositions() {
  const list = Object.values(loadPositions()).sort((a, b) => (b.openedAt || 0) - (a.openedAt || 0));
  const open = list.filter((p) => p.status === "open");
  $("pos-count").textContent = `${open.length} open`;

  const container = $("positions-list");
  if (list.length === 0) {
    container.innerHTML = `<div class="empty">No positions yet. Board Mutinynet sats and lock USD/EUR above.</div>`;
    tickInterest();
    return 0;
  }
  const nowMs = Date.now();
  const nowSecs = Math.floor(nowMs / 1000);
  const configuredWt = getWatchtowerPubkey();
  container.innerHTML = list
    .map((p) => {
      const isOpen = p.status === "open";
      const isLong = p.side === "long";
      const pCur = (p.currency || "USD").toUpperCase();
      const pSym = curSym(pCur);
      const pNotional = Number(p.notional ?? p.notionalUsd ?? 0);
      const pSpot = spots[pCur] || p.openSpotPrice || p.openSpotUsd || 0;
      const interest = computeAccruedInterestUsd(p, nowMs);
      const yieldBps = Number(p.fundingRateBpsPerDay ?? (isLong ? -3 : 3));
      const estSats = isOpen
        ? estimatePositionSats(p, pSpot, interest)
        : p.userPayoutSats || p.userCollateralSats;
      const liqPrice = isLong ? Math.round(Number(p.liquidationPrice || Number(p.openSpotPrice ?? p.openSpotUsd) * 0.5)) : 0;
      const longValFiat = isLong && pSpot > 0 ? (estSats / 1e8) * pSpot : pNotional;
      const longPnlFiat = longValFiat - pNotional;
      const longPnlPct = pNotional > 0 ? (longPnlFiat / pNotional) * 100 : 0;
      const longPnlSign = longPnlFiat >= 0 ? "+" : "-";
      const rollHint = isOpen ? getRollReason(p, nowSecs) : null;
      const wtStatusHtml = configuredWt
        ? p.watchtowerRegistered
          ? `<span class="accent-green">🛡 Protected by Watchtower</span>`
          : `<button class="link-btn" data-wt-nip17="${p.positionId}">🛡 Sync to Watchtower</button>`
        : `<button class="link-btn warn" data-setup-wt="1">⚠ No Watchtower — Set up in Settings →</button>`;
      return `
        <div class="pos-item">
          <div class="pos-top">
            <strong>${isLong ? `🚀 2× Long BTC (${fmtFiat(pNotional, pCur)} margin)` : `${fmtFiat(pNotional, pCur)} ${pCur} Peg`} ${p.lpName ? `<span class="muted">(${p.lpName})</span>` : ""}</strong>
            <span class="pill ${isOpen ? "ok" : "muted-pill"}">${p.status}</span>
          </div>
          <div class="pos-meta">
            ID: <code>${p.positionId}</code>${p.rollCount ? ` · <span class="accent-green">Rolled ${p.rollCount}×</span>` : ""} · ${isLong ? "Funding" : "Yield"}: <span class="${yieldBps >= 0 ? "accent-green" : "accent-red"}">${fmtYield(yieldBps)}</span><br/>
            Entry: ${pSym}${Number(p.openSpotPrice ?? p.openSpotUsd).toLocaleString()}${isLong ? ` · Liq: <strong>${pSym}${liqPrice.toLocaleString()}</strong>` : ""} · Collateral: ${p.totalCollateralSats.toLocaleString()} sats<br/>
            ${
              isOpen
                ? (isLong
                    ? `Live P&amp;L: <strong data-interest-pos="${p.positionId}" class="${longPnlFiat >= 0 ? "accent-green" : "accent-red"}">${longPnlSign}${pSym}${Math.abs(longPnlFiat).toFixed(2)} (${longPnlSign}${Math.abs(longPnlPct).toFixed(1)}%) · Est. payout: ${estSats.toLocaleString()} sats</strong>`
                    : `Accrued interest: <strong data-interest-pos="${p.positionId}" class="${interest >= 0 ? "accent-green" : "accent-red"}">${fmtInterestFiat(interest, pCur)} · Est. payout: ${estSats.toLocaleString()} sats</strong>`) +
                  (Number(p.totalPaidInterestSats || 0) > 0
                    ? `<br/><span class="accent-green">Paid to Available BTC: +${Number(p.totalPaidInterestSats).toLocaleString()} sats</span>`
                    : "")
                : `Closed at ${pSym}${p.closeSpotUsd} → User: ${p.userPayoutSats} sats${p.accruedInterestUsd ? ` (incl. ${fmtInterestFiat(p.accruedInterestUsd, pCur)} ${isLong ? "funding" : "yield"})` : ""}`
            }
          </div>
          ${
            isOpen && rollHint
              ? `<div class="roll-hint ${rollHint.good ? "good" : ""}">${rollHint.text}</div>`
              : ""
          }
          ${
            isOpen
              ? `<div class="action-row">
                   <button class="btn ${rollHint?.urgent || rollHint?.good ? "primary" : "secondary"} small" data-roll="${p.positionId}">Roll Position</button>
                   <button class="btn danger small" data-close="${p.positionId}">Close at Spot</button>
                 </div>
                 <div class="wt-footer">
                   ${wtStatusHtml}
                   <div style="display:flex;gap:10px;align-items:center">
                     ${
                       p.disputeScriptHex
                         ? `<button class="link-btn warn" data-dispute="${p.positionId}" title="Emergency mid-term exit via k-of-n Nostracles if LP is offline">⚡ Force Exit</button>`
                         : ""
                     }
                     <button class="link-btn" data-wt="${p.positionId}">Backup JSON</button>
                   </div>
                 </div>`
              : ""
          }
        </div>`;
    })
    .join("");

  container.querySelectorAll("[data-copy-text]").forEach((el) => {
    el.onclick = async () => {
      const txt = el.getAttribute("data-copy-text");
      await navigator.clipboard.writeText(txt);
      showToast(`Copied ${shortNpub(txt)}`);
    };
  });

  container.querySelectorAll("[data-roll]").forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.getAttribute("data-roll");
      btn.disabled = true;
      btn.textContent = "Rolling…";
      try {
        const rolled = await appWallet.rollPosition(id);
        const rCur = (rolled.currency || "USD").toUpperCase();
        const rSym = curSym(rCur);
        const paidSats = Number(rolled.lastRollUserSurplusSats || 0);
        const carried = Number(rolled.carriedInterestUsd || 0);
        const detail =
          paidSats > 0
            ? `+${paidSats.toLocaleString()} sats (yield & rebalance) added to your Available BTC balance`
            : `${fmtInterestFiat(carried, rCur)} yield carried forward (pays out to BTC balance once ≥ 330 sats)`;
        showToast(`Rolled #${rolled.rollCount} at ${rSym}${rolled.openSpotUsd} — ${detail}`, 5500);
        await refresh();
      } catch (e) {
        showToast(`Roll failed: ${e.message}`, 5000);
        btn.disabled = false;
        btn.textContent = "Roll";
      }
    };
  });

  container.querySelectorAll("[data-dispute]").forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.getAttribute("data-dispute");
      const ok = window.confirm(
        "Request an emergency mid-term On-Demand Dispute exit from the k-of-n Nostracle quorum via NIP-17?\n\nOnly needed if the LP is offline."
      );
      if (!ok) return;
      btn.disabled = true;
      btn.textContent = "Signing…";
      try {
        const pos = loadPositions()[id];
        const cur = (pos?.currency || activeCurrency || "USD").toUpperCase();
        const res = await appWallet.forceDisputeExit(id, spots[cur] || spots.USD || null);
        await navigator.clipboard?.writeText(res.rawTxHex).catch(() => {});
        showToast(
          res.broadcastTxid
            ? `⚡ ${res.signedCount}/${res.totalOracles} Nostracles signed! Broadcasted: ${res.broadcastTxid.slice(0, 14)}…`
            : `⚡ ${res.signedCount}/${res.totalOracles} Nostracles signed! Payout: ${res.userPayoutSats.toLocaleString()} sats (signed tx copied)`,
          7000
        );
      } catch (e) {
        showToast(`Dispute exit failed: ${e.message}`, 6000);
      } finally {
        btn.disabled = false;
        btn.textContent = "⚡ Force Exit";
      }
    };
  });

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
        showToast(`Exported ${pkg.unroll_txs.length}-hop watchtower JSON (${pkg.payouts?.length || 0} adaptor payouts)`);
      } catch (e) {
        showToast(`Export failed: ${e.message}`, 5000);
      } finally {
        btn.disabled = false;
      }
    };
  });

  container.querySelectorAll("[data-setup-wt]").forEach((btn) => {
    btn.onclick = () => {
      $("settings-panel").classList.remove("hidden");
      $("wt-pubkey-input").focus();
      $("settings-panel").scrollIntoView({ behavior: "smooth" });
    };
  });

  container.querySelectorAll("[data-wt-nip17]").forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.getAttribute("data-wt-nip17");
      btn.disabled = true;
      btn.textContent = "Syncing…";
      try {
        const res = await appWallet.registerWithWatchtower(id);
        showToast(`Synced ${res.unrollHops}-hop pkg (${res.payouts} payouts) to Watchtower via NIP-17`);
        await refresh();
      } catch (e) {
        showToast(`Watchtower sync failed: ${e.message}`, 5000);
        btn.disabled = false;
        btn.textContent = "🛡 Sync to Watchtower";
      }
    };
  });
}

function buildUnifiedReceiveUri() {
  if (!lastVaultAddr) return "";
  if (receiveContext === "vault") {
    return `bitcoin:${lastVaultAddr}`;
  }
  const params = new URLSearchParams();
  if (activeLnAmountSats > 0) {
    params.set("amount", (activeLnAmountSats / 1e8).toFixed(8).replace(/0+$/, "").replace(/\.$/, ""));
  }
  if (lastArkAddr) params.set("ark", lastArkAddr);
  if (activeLnInvoice) params.set("lightning", activeLnInvoice);
  const qs = params.toString();
  return qs ? `bitcoin:${lastVaultAddr}?${qs}` : `bitcoin:${lastVaultAddr}`;
}

async function renderReceiveQr() {
  const uri = buildUnifiedReceiveUri();
  const canvas = $("recv-qr-canvas");
  if ($("unified-uri")) $("unified-uri").textContent = uri || "—";
  if (!canvas || !uri) return;
  try {
    await QRCode.toCanvas(canvas, uri, { width: 192, margin: 1, errorCorrectionLevel: "M" });
  } catch {}
}

function parseBip21Input(raw) {
  const s = String(raw || "").trim();
  if (!/^bitcoin:/i.test(s)) return null;
  const withoutScheme = s.replace(/^bitcoin:/i, "");
  const [l1Addr, queryStr = ""] = withoutScheme.split("?");
  const params = new URLSearchParams(queryStr);
  const ark = params.get("ark") || "";
  const lightning = params.get("lightning") || "";
  const amountBtc = Number(params.get("amount") || 0);
  const amountSats = amountBtc > 0 ? Math.round(amountBtc * 1e8) : 0;
  return { l1Addr: l1Addr.trim(), ark: ark.trim(), lightning: lightning.trim(), amountSats };
}

function detectSendMode(raw) {
  const bip21 = parseBip21Input(raw);
  if (bip21) {
    if (sendSource === "vault") {
      return bip21.l1Addr
        ? { mode: "vault-l1", target: bip21.l1Addr, amountSats: bip21.amountSats, label: "🏦 Vault Onchain (BIP-21)", cls: "pill best" }
        : { mode: "invalid", target: "", label: "No L1 address in BIP-21", cls: "pill err" };
    }
    if (bip21.ark) {
      return { mode: "ark", target: bip21.ark, amountSats: bip21.amountSats, label: "⚡ BIP-21 → Arkade (0 fee)", cls: "pill ok" };
    }
    if (bip21.lightning) {
      return { mode: "ln", target: bip21.lightning, amountSats: bip21.amountSats, label: "⚡ BIP-21 → Lightning", cls: "pill ok" };
    }
    if (bip21.l1Addr) {
      return { mode: "l1", target: bip21.l1Addr, amountSats: bip21.amountSats, label: "⛓ BIP-21 → Bitcoin L1", cls: "pill best" };
    }
  }
  const a = String(raw || "").trim().toLowerCase().replace(/^lightning:/, "");
  if (!a) return { mode: "none", target: "", label: "Enter address or invoice", cls: "pill muted-pill" };
  if (sendSource === "vault") {
    if (a.startsWith("tb1") || a.startsWith("bc1") || a.startsWith("m") || a.startsWith("n") || a.startsWith("2")) {
      return { mode: "vault-l1", target: String(raw).trim(), label: "🏦 Vault Onchain (0 timelock)", cls: "pill best" };
    }
    if (a.startsWith("lnbc") || a.startsWith("lntb") || a.startsWith("lntbs") || a.startsWith("tark1") || a.startsWith("ark1")) {
      return { mode: "needs-spending", target: String(raw).trim(), label: "⚡ Requires Spending Wallet", cls: "pill best" };
    }
    return { mode: "invalid", target: "", label: "Unknown address", cls: "pill err" };
  }
  if (a.startsWith("lnbc") || a.startsWith("lntb") || a.startsWith("lntbs")) {
    return { mode: "ln", target: a, label: "⚡ Lightning (Boltz swap)", cls: "pill ok" };
  }
  if (a.startsWith("tark1") || a.startsWith("ark1")) {
    return { mode: "ark", target: String(raw).trim(), label: "⚡ Instant Arkade (0 fee)", cls: "pill ok" };
  }
  if (a.startsWith("tb1") || a.startsWith("bc1") || a.startsWith("m") || a.startsWith("n") || a.startsWith("2")) {
    return { mode: "l1", target: String(raw).trim(), label: "⛓ Bitcoin Onchain (L1)", cls: "pill best" };
  }
  return { mode: "invalid", target: "", label: "Unknown address", cls: "pill err" };
}

function getSendAmountSats() {
  const raw = Number($("send-sats-input")?.value || 0);
  if (sendSource === "stable") {
    const sp = spots[activeCurrency] || spots.USD || 60000;
    return sp > 0 && raw > 0 ? Math.round((raw / sp) * 1e8) : 0;
  }
  return Math.floor(raw);
}

function updateSendUi() {
  const raw = $("send-addr-input").value;
  const info = detectSendMode(raw);
  const pill = $("send-mode-pill");
  const satsInp = $("send-sats-input");
  const sp = spots[activeCurrency] || spots.USD || 0;
  const isStable = sendSource === "stable";

  if (info.mode === "ln" && appWallet) {
    try {
      const dec = appWallet.decodeLightningInvoice(info.target || raw);
      if (dec.amountSats > 0) {
        satsInp.value =
          isStable && sp > 0 ? ((dec.amountSats / 1e8) * sp).toFixed(2) : dec.amountSats;
        satsInp.readOnly = true;
      } else {
        satsInp.readOnly = false;
      }
    } catch {
      satsInp.readOnly = false;
    }
  } else {
    satsInp.readOnly = false;
    if (info.amountSats > 0 && !satsInp.value) {
      satsInp.value =
        isStable && sp > 0 ? ((info.amountSats / 1e8) * sp).toFixed(2) : info.amountSats;
    }
  }

  pill.textContent = info.label;
  pill.className = info.cls;
  const sats = getSendAmountSats();
  const rawAmt = Number(satsInp.value || 0);
  if (isStable) {
    $("send-fiat-est").textContent = sats > 0 ? `≈ ${sats.toLocaleString()} sats` : "";
  } else {
    $("send-fiat-est").textContent =
      sats > 0 && sp > 0 ? `≈ ${fmtFiat((sats / 1e8) * sp, activeCurrency)}` : "";
  }

  // Live source-aware availability + one-click top-up hints from Vault / Spending / Stable USD
  const bar = $("send-avail-bar");
  if (!bar) return;
  const parts = [];
  if (info.mode === "needs-spending") {
    bar.className = "roll-hint";
    parts.push(
      `⚡ Lightning &amp; Arkade payments send from <strong>Spending</strong> (Available: <strong>${lastAvailSats.toLocaleString()} sats</strong>) ` +
        `<button class="link-btn warn" data-send-action="switch-spending">Switch to Spending →</button>`
    );
    if (lastVaultSats > 0) {
      parts.push(
        `Vault (L1): ${lastVaultSats.toLocaleString()} sats <button class="link-btn" data-send-action="vault-to-spending">Move to Spending →</button>`
      );
    }
    if (lastPeggedSats > 0) {
      parts.push(
        `Stable ${activeCurrency}: ≈ ${lastPeggedSats.toLocaleString()} sats <button class="link-btn" data-send-action="open-positions">Release to sats →</button>`
      );
    }
    bar.innerHTML = parts.join("<br/>");
  } else if (sendSource === "stable") {
    const spendingFiat = sp > 0 ? (lastAvailSats / 1e8) * sp : 0;
    const totalFiatAvail = lastPeggedFiat + spendingFiat;
    const short = rawAmt > totalFiatAvail + 0.005;
    bar.className = short ? "roll-hint" : "roll-hint good";
    parts.push(
      `🛡 Available: <strong>${fmtFiat(lastPeggedFiat, activeCurrency)}</strong> Stable ${activeCurrency}` +
        (spendingFiat > 0 ? ` + <strong>${fmtFiat(spendingFiat, activeCurrency)}</strong> Spending BTC` : "") +
        ` = <strong>${fmtFiat(totalFiatAvail, activeCurrency)}</strong>` +
        (short ? ` <span class="accent-red">(need ${fmtFiat(rawAmt - totalFiatAvail, activeCurrency)} more)</span>` : "")
    );
    parts.push(
      `<span class="muted">Auto-liquidates soonest-expiring &amp; lowest-APR Stable positions first to fund this payment.</span>`
    );
    if (short && lastVaultSats > 0) {
      const vaultFiat = sp > 0 ? (lastVaultSats / 1e8) * sp : 0;
      parts.push(
        `Vault (L1) has <strong>${fmtFiat(vaultFiat, activeCurrency)}</strong> (${lastVaultSats.toLocaleString()} sats) — <button class="link-btn warn" data-send-action="vault-to-spending">Move from Vault →</button>`
      );
    }
    bar.innerHTML = parts.join("<br/>");
  } else if (sendSource === "vault") {
    const short = sats > lastVaultSats;
    bar.className = short ? "roll-hint" : "roll-hint good";
    parts.push(
      `🏦 Available in <strong>Bitcoin Vault (L1)</strong>: <strong>${lastVaultSats.toLocaleString()} sats</strong>` +
        (short ? ` <span class="accent-red">(need ${(sats - lastVaultSats).toLocaleString()} more sats)</span>` : "")
    );
    if ((short || lastVaultSats === 0) && lastAvailSats > 0) {
      parts.push(
        `Spending (Arkade) has <strong>${lastAvailSats.toLocaleString()} sats</strong> — <button class="link-btn warn" data-send-action="spending-to-vault">Move to Vault</button> or <button class="link-btn" data-send-action="switch-spending">Send from Spending</button>`
      );
    }
    if ((short || lastVaultSats === 0) && lastPeggedSats > 0) {
      parts.push(
        `Stable ${activeCurrency} has <strong>≈ ${lastPeggedSats.toLocaleString()} sats</strong> — <button class="link-btn" data-send-action="open-positions">Close position first</button>`
      );
    }
    bar.innerHTML = parts.join("<br/>");
  } else {
    const short = sats > lastAvailSats;
    bar.className = short ? "roll-hint" : "roll-hint good";
    parts.push(
      `⚡ Available in <strong>Spending</strong>: <strong>${lastAvailSats.toLocaleString()} sats</strong>` +
        (short ? ` <span class="accent-red">(need ${(sats - lastAvailSats).toLocaleString()} more sats)</span>` : "")
    );
    if ((short || lastAvailSats === 0) && lastVaultSats > 0) {
      parts.push(
        `Vault (L1) has <strong>${lastVaultSats.toLocaleString()} sats</strong> — <button class="link-btn warn" data-send-action="vault-to-spending">Move from Vault first →</button>`
      );
    }
    if ((short || lastAvailSats === 0) && lastPeggedSats > 0) {
      parts.push(
        `Stable ${activeCurrency} has <strong>≈ ${lastPeggedSats.toLocaleString()} sats</strong> — <button class="link-btn warn" data-send-action="open-positions">Release Stable ${activeCurrency} to sats →</button>`
      );
    }
    bar.innerHTML = parts.join("<br/>");
  }

  bar.querySelectorAll("[data-send-action]").forEach((btn) => {
    btn.onclick = () => {
      const act = btn.getAttribute("data-send-action");
      if (act === "switch-spending") {
        sendSource = "spending";
        $("send-heading").textContent = "Send from Spending";
        $("send-addr-label").innerHTML =
          "Recipient (<code>bitcoin:…</code> BIP-21, <code>lntbs…</code> Lightning, <code>tark1…</code> instant, or <code>tb1…</code> L1)";
        updateSendUi();
      } else if (act === "vault-to-spending") {
        $("btn-vault-up")?.click();
      } else if (act === "spending-to-vault") {
        $("btn-vault-down")?.click();
      } else if (act === "open-positions") {
        $("send-panel").classList.add("hidden");
        const body = $("positions-body");
        if (body?.classList.contains("hidden")) $("btn-to-sats")?.click();
        else $("positions-card")?.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    };
  });
}

let lnInfoLoaded = false;
let activeLnUnsub = null;

async function loadLightningFeeHint() {
  if (lnInfoLoaded || !appWallet) return;
  lnInfoLoaded = true;
  const hint = $("ln-fee-hint");
  if (!hint) return;
  hint.textContent = "· loading Boltz fees…";
  const info = await appWallet.getLightningInfo();
  if (info.available && info.fees) {
    const revPct = info.fees.reverse?.percentage ?? info.fees.percentage;
    const min = info.limits?.min;
    const max = info.limits?.max;
    const parts = [];
    if (revPct !== undefined) parts.push(`${revPct}% fee`);
    if (min && max) parts.push(`${Number(min).toLocaleString()}–${Number(max).toLocaleString()} sats`);
    hint.textContent = parts.length ? `· ${parts.join(" · ")}` : "";
  } else {
    hint.textContent = "· Boltz Mutinynet offline";
    lnInfoLoaded = false;
  }
}

function renderHistory(txs) {
  const list = Array.isArray(txs) ? txs.slice(0, 10) : [];
  $("tx-count").textContent = `${list.length} recent`;
  const box = $("tx-list");
  if (list.length === 0) {
    box.innerHTML = `<div class="empty">No Arkade transactions yet.</div>`;
    return;
  }
  // Map position txids to human-readable conversion labels (sats → USD / USD → sats)
  const posByTx = new Map();
  for (const p of Object.values(loadPositions())) {
    const cur = (p.currency || "USD").toUpperCase();
    const isLong = p.side === "long";
    if (p.vtxoTxid) {
      posByTx.set(p.vtxoTxid, {
        label: isLong ? "🚀 sats → 2× Long BTC" : `⇄ sats → ${cur}`,
        cls: "accent-green",
      });
    }
    if (p.prevVtxoTxid) {
      posByTx.set(p.prevVtxoTxid, {
        label: isLong ? "↻ Rolled 2× Long BTC" : `↻ Rolled ${cur}`,
        cls: "accent-green",
      });
    }
    if (p.closeTxid) {
      posByTx.set(p.closeTxid, {
        label: isLong ? "🚀 2× Long BTC → sats" : `⇄ ${cur} → sats`,
        cls: "accent-green",
      });
    }
  }
  box.innerHTML = list
    .map((tx) => {
      const isRecv = String(tx.type || "").toUpperCase().includes("RECEIVED");
      const amt = Number(tx.amount || 0);
      const id = tx.key?.arkTxid || tx.key?.commitmentTxid || tx.key?.boardingTxid || "";
      const posMeta = id ? posByTx.get(id) : null;
      const label = posMeta ? posMeta.label : isRecv ? "↓ Received" : "↑ Sent";
      const labelCls = posMeta ? posMeta.cls : isRecv ? "accent-green" : "";
      const when = tx.createdAt ? new Date(tx.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
      return `
        <div class="tx-row">
          <div>
            <strong class="${labelCls}">${label}</strong>
            <span class="muted">${tx.settled ? "settled" : "preconfirmed"}${when ? ` · ${when}` : ""}</span>
          </div>
          <div style="text-align:right">
            <strong class="${isRecv ? "accent-green" : ""}">${isRecv ? "+" : "-"}${amt.toLocaleString()} sats</strong>
            ${id ? `<div class="muted"><code>${id.slice(0, 10)}…</code></div>` : ""}
          </div>
        </div>`;
    })
    .join("");
}

let autoOnboardInFlight = false;
let autoOnboardFailed = false;
let incomingPollTimer = null;

function setIncomingBanner(html, show = true) {
  const el = $("incoming-banner");
  if (!el) return;
  if (!show) {
    el.classList.add("hidden");
    el.innerHTML = "";
    return;
  }
  el.innerHTML = html;
  el.classList.remove("hidden");
  const retryBtn = el.querySelector("[data-retry-onboard]");
  if (retryBtn) {
    retryBtn.onclick = () => {
      autoOnboardFailed = false;
      refresh();
    };
  }
}

async function triggerAutoOnboard(confirmedSats) {
  if (autoOnboardInFlight || !appWallet) return;
  autoOnboardInFlight = true;
  autoOnboardFailed = false;
  setIncomingBanner(
    `<span>⏳ Incoming Bitcoin deposit (<strong>+${confirmedSats.toLocaleString()} sats</strong>) — finalizing to your wallet…</span>`
  );
  try {
    await appWallet.onboard((ev) => {
      if (ev?.type) {
        setIncomingBanner(
          `<span>⏳ Finalizing Bitcoin deposit (<strong>+${confirmedSats.toLocaleString()} sats</strong>) · ${ev.type}…</span>`
        );
      }
    });
    showToast(`+${confirmedSats.toLocaleString()} sats credited to your Available BTC`);
    setIncomingBanner("", false);
    await refresh();
  } catch (e) {
    autoOnboardFailed = true;
    setIncomingBanner(
      `<span>⚠ Incoming deposit (+${confirmedSats.toLocaleString()} sats) paused: ${e.message}</span> <button class="link-btn warn" data-retry-onboard="1">Retry</button>`
    );
  } finally {
    autoOnboardInFlight = false;
  }
}

let wtAutoSyncBusy = false;
async function autoSyncWatchtower() {
  if (wtAutoSyncBusy || !appWallet) return;
  const wtPub = getWatchtowerPubkey();
  if (!wtPub) return;
  const pending = Object.values(loadPositions()).filter(
    (p) => p.status === "open" && (!p.watchtowerRegistered || p.watchtowerPubkey !== wtPub)
  );
  if (pending.length === 0) return;
  wtAutoSyncBusy = true;
  try {
    let syncedAny = false;
    for (const p of pending) {
      try {
        await appWallet.registerWithWatchtower(p.positionId, wtPub);
        syncedAny = true;
      } catch {
        // Keep manual Retry link if watchtower/relays are temporarily unreachable
      }
    }
    if (syncedAny) renderPositions();
  } finally {
    wtAutoSyncBusy = false;
  }
}

async function refresh() {
  if (!appWallet) return;
  try {
    const [addrs, bal, vaultBal, history] = await Promise.all([
      appWallet.getAddresses(),
      appWallet.getBalance(),
      appWallet.getVaultBalance(),
      appWallet.getTransactionHistory(),
    ]);
    renderHistory(history);
    lastArkAddr = addrs.arkAddress;
    lastVaultAddr = addrs.vaultAddress;
    $("ark-addr").textContent = addrs.arkAddress;
    $("vault-addr").textContent = addrs.vaultAddress;
    renderReceiveQr();
    lastAvailSats = Number(bal.available || 0);
    lastVaultSats = Number(vaultBal.total || 0);
    $("avail-sats").textContent = `${lastAvailSats.toLocaleString()} sats`;
    $("vault-sats").textContent = `${lastVaultSats.toLocaleString()} sats`;
    $("vault-sub").textContent =
      vaultBal.unconfirmed > 0
        ? `0 timelock · +${vaultBal.unconfirmed.toLocaleString()} pending`
        : "0 timelock · L1";
    const boardingConfirmed = Number(bal.boarding?.confirmed || 0);
    const boardingTotal = Number(bal.boarding?.total || 0);

    if (boardingConfirmed > 0) {
      if (!autoOnboardInFlight && !autoOnboardFailed) {
        triggerAutoOnboard(boardingConfirmed);
      }
    } else if (boardingTotal > 0) {
      autoOnboardFailed = false;
      setIncomingBanner(
        `<span>⏳ Incoming Bitcoin deposit (<strong>+${boardingTotal.toLocaleString()} sats</strong>) — waiting for 1 confirmation…</span>`
      );
      if (!incomingPollTimer) {
        incomingPollTimer = setTimeout(() => {
          incomingPollTimer = null;
          refresh();
        }, 15_000);
      }
    } else {
      autoOnboardFailed = false;
      if (incomingPollTimer) {
        clearTimeout(incomingPollTimer);
        incomingPollTimer = null;
      }
      if (!autoOnboardInFlight) setIncomingBanner("", false);
    }

    const selected = getSelectedLp();
    let lpOk = false;
    try {
      const health = await appWallet.fetchLpHealth(selected);
      if (health.oracleQuorum?.oracles?.length) renderNostracles(health.oracleQuorum);
      if (health.spotUsd) spots.USD = Number(health.spotUsd);
      if (health.spotEur) spots.EUR = Number(health.spotEur);
      const shownSpot = spots[activeCurrency] || spots.USD || 0;
      $("spot-pill").textContent = `BTC ${curSym()}${shownSpot.toLocaleString()}`;
      $("lp-status").textContent = `${health.lpName || selected.lpName}${selected.preferNip17 ? " (NIP-17)" : ""}: ${Number(health.arkBalance?.available || 0).toLocaleString()} sats`;
      $("lp-status").className = "pill ok";
      lpOk = true;
    } catch {
      $("lp-status").textContent = `${selected.lpName} offline`;
      $("lp-status").className = "pill err";
    }

    renderPositions();
    tickInterest();
    autoSyncWatchtower();
    $("open-btn").disabled = !lpOk;
  } catch (e) {
    showToast(`Sync error: ${e.message}`, 4500);
  }
}

async function fetchQuoteUi() {
  const amt = getActiveTradeNotionalFiat();
  if (amt <= 0) return;
  const selected = getSelectedLp();
  const cur = activeCurrency;
  const side = activeSide;
  const sym = curSym(cur);
  $("quote-box").textContent = `Fetching live ${side === "long" ? "2× Long BTC" : cur} quote from ${selected.lpName}…`;
  try {
    const q = await appWallet.requestQuote(amt, selected, cur, side);
    const sp = Number(q.spotPrice ?? q.spotUsd);
    spots[cur] = sp;
    $("spot-pill").textContent = `BTC ${sym}${sp.toLocaleString()}`;
    const funding = q.fundingRateBpsPerDay ?? (side === "long" ? -3 : 3);
    const liqLine =
      side === "long"
        ? ` · <strong>2× Leverage</strong> · Liq: <strong>${sym}${Number(q.liquidationPrice || Math.round(sp * 0.5)).toLocaleString()}</strong>`
        : "";
    const effEntry = Number(q.effectiveSpotUsd ?? sp);
    const spreadBps = Math.max(0, Number(q.spreadBps ?? selected.spreadBps ?? 0));
    const spreadPct = (spreadBps / 100).toFixed(2);
    const notionalFiat = Number(q.notional ?? q.notionalUsd ?? (side === "long" ? (amt / 1e8) * sp : amt));
    const termSecs = Number(q.termSecs ?? selected.termSecs ?? 86400);
    const termDays = Math.max(1, Math.round(termSecs / 86400));
    const termLabel = termDays === 1 ? "1d" : `${termDays}d`;
    const entryFeeFiat = notionalFiat * (spreadBps / 10_000);
    const termYieldFiat = notionalFiat * (funding / 10_000) * termDays;
    const netTermFiat = termYieldFiat - entryFeeFiat;
    const fmtSmallFiat = (v) => {
      const abs = Math.abs(v);
      const dec = abs > 0 && abs < 0.01 ? 4 : abs < 0.1 ? 3 : 2;
      return `${v < 0 ? "-" : ""}${sym}${abs.toFixed(dec)}`;
    };
    const breakEvenDays =
      side === "short" && funding > 0 && spreadBps > 0 ? Math.ceil(spreadBps / funding) : null;
    const netHint =
      side === "short"
        ? netTermFiat >= 0
          ? `<span class="accent-green"><strong>+${fmtSmallFiat(netTermFiat)} net</strong></span>`
          : `<span style="color:var(--accent)"><strong>${fmtSmallFiat(netTermFiat)} net</strong>${
              breakEvenDays ? ` (break-even ~${breakEvenDays}d)` : ""
            }</span>`
        : `<span class="accent-red"><strong>${fmtSmallFiat(netTermFiat)}</strong> total cost over ${termLabel}</span>`;
    $("quote-box").innerHTML = `
      LP: <strong>${q.lpName || selected.lpName}</strong> · Entry: <strong>${sym}${effEntry.toLocaleString()}</strong> · Term: <strong>${termLabel}</strong>${liqLine}<br/>
      Entry fee: <strong>${fmtSmallFiat(entryFeeFiat)}</strong> (${spreadPct}%) · <span class="${funding >= 0 ? "accent-green" : "accent-red"}"><strong>${fmtYield(funding)}</strong></span><br/>
      ${termLabel} ${side === "long" ? "funding" : "yield"}: <strong class="${termYieldFiat >= 0 ? "accent-green" : "accent-red"}">${termYieldFiat >= 0 ? "+" : ""}${fmtSmallFiat(termYieldFiat)}</strong> · ${netHint}<br/>
      <span class="muted">Your margin: ${q.userCollateralSats.toLocaleString()} sats · LP matches: ${q.lpCollateralSats.toLocaleString()} sats</span>
    `;
  } catch (e) {
    $("quote-box").textContent = `Quote error (${selected.lpName}): ${e.message}`;
  }
}

function applyCurrencyUi() {
  const sym = curSym();
  const isLong = activeSide === "long";
  document.querySelectorAll(".cur-btn").forEach((b) => {
    b.classList.toggle("active", b.getAttribute("data-cur") === activeCurrency);
  });
  document.querySelectorAll(".side-btn[data-side]").forEach((b) => {
    b.classList.toggle("active", b.getAttribute("data-side") === activeSide);
  });
  if ($("side-short")) $("side-short").textContent = `🛡 Stable ${activeCurrency}`;
  $("lock-heading").innerHTML = `<span class="caret">▸</span> ${
    isLong ? `Open 2× Long BTC (${activeCurrency} Margin)` : `Lock ${activeCurrency} Value`
  }`;
  $("open-btn").textContent = isLong ? `Open 2× Long BTC` : `Lock ${activeCurrency} Now`;
  if ($("pegged-label")) $("pegged-label").textContent = `🛡 Stable ${activeCurrency}`;
  if ($("btn-to-fiat")) $("btn-to-fiat").textContent = `↑ To ${activeCurrency}`;
  const longPresets = [2000, 5000, 10000, 25000];
  document.querySelectorAll(".chip[data-usd]").forEach((c, idx) => {
    if (isLong) {
      const satsVal = longPresets[idx] || 5000;
      c.setAttribute("data-sats", String(satsVal));
      c.textContent = `${satsVal / 1000}k`;
    } else {
      c.textContent = `${sym}${c.getAttribute("data-usd")}`;
    }
  });
  const inp = $("usd-input");
  if (inp) {
    inp.step = isLong ? "500" : "1";
    inp.min = isLong ? "1000" : "1";
    inp.placeholder = isLong ? "sats" : activeCurrency;
    const activeChip = document.querySelector(".chip[data-usd].active");
    if (activeChip) {
      inp.value = isLong
        ? activeChip.getAttribute("data-sats") || "5000"
        : activeChip.getAttribute("data-usd") || "2";
    }
  }
  const sp = spots[activeCurrency];
  if (sp) $("spot-pill").textContent = `BTC ${sym}${sp.toLocaleString()}`;
}

async function boot() {
  $("relays-input").value = getNostrRelays().join(", ");
  $("wt-pubkey-input").value = getWatchtowerPubkey();
  function stopStableAutoReceive() {
    if (stableRecvPollTimer) {
      clearInterval(stableRecvPollTimer);
      stableRecvPollTimer = null;
    }
    stableRecvBusy = false;
  }

  function startStableAutoReceive() {
    stopStableAutoReceive();
    stableRecvBaselineSats = lastAvailSats;
    const banner = $("stable-recv-banner");
    const cur = activeCurrency;
    const sym = curSym(cur);
    banner.innerHTML = `🛡 <strong>Auto-Stabilize ON</strong> — incoming sats (≥ ${sym}1) will automatically lock into <strong>Stable ${cur}</strong> (keep this tab open).`;
    banner.classList.remove("hidden");

    stableRecvPollTimer = setInterval(async () => {
      if (stableRecvBusy || !appWallet || $("deposit-panel").classList.contains("hidden") || receiveContext !== "stable") {
        if ($("deposit-panel").classList.contains("hidden") || receiveContext !== "stable") stopStableAutoReceive();
        return;
      }
      stableRecvBusy = true;
      try {
        const bal = await appWallet.getBalance();
        const curAvail = Number(bal.available || 0);
        const deltaSats = curAvail - stableRecvBaselineSats;
        if (deltaSats >= 1_000) {
          const sp = spots[cur] || spots.USD || 60000;
          const deltaFiat = Number(((deltaSats / 1e8) * sp).toFixed(2));
          if (deltaFiat >= 1) {
            const selected = getSelectedLp();
            banner.innerHTML = `⏳ Received <strong>+${deltaSats.toLocaleString()} sats</strong> — auto-locking <strong>${fmtFiat(deltaFiat, cur)} Stable ${cur}</strong> via ${selected.lpName}…`;
            const pos = await appWallet.openPosition(deltaFiat, selected, selected.lpName, cur, "short");
            stableRecvBaselineSats = Number((await appWallet.getBalance()).available || 0);
            banner.innerHTML = `✅ Received +${deltaSats.toLocaleString()} sats → Auto-locked <strong>${fmtFiat(pos.notional ?? pos.notionalUsd, cur)} Stable ${cur}</strong>!`;
            showToast(`🛡 Auto-stabilized +${deltaSats.toLocaleString()} sats into ${fmtFiat(deltaFiat, cur)} Stable ${cur}!`, 5500);
            await refresh();
          }
        }
      } catch (e) {
        banner.innerHTML = `⚠ Auto-Stabilize paused: ${e.message} (your sats are safe in Spending BTC).`;
      } finally {
        stableRecvBusy = false;
      }
    }, 4_000);
  }

  function openReceivePanel(ctx) {
    const panel = $("deposit-panel");
    if (!panel.classList.contains("hidden") && receiveContext === ctx) {
      panel.classList.add("hidden");
      stopStableAutoReceive();
      return;
    }
    receiveContext = ctx;
    $("send-panel").classList.add("hidden");
    $("vault-panel").classList.add("hidden");
    const isVault = ctx === "vault";
    const isStable = ctx === "stable";
    $("recv-heading").textContent = isVault
      ? "Receive to Bitcoin Vault (Onchain L1)"
      : isStable
      ? `Receive Stable ${activeCurrency} (Auto-Stabilize)`
      : "Receive Bitcoin (Unified BIP-21 QR)";
    $("recv-qr-caption").textContent = isVault
      ? "Pure onchain Bitcoin L1 (0 timelock — never expires)"
      : isStable
      ? `1 Unified QR: incoming Arkade or Lightning sats auto-lock into Stable ${activeCurrency}`
      : "1 Unified QR: works with Arkade, Lightning & Bitcoin L1 wallets";
    const net = String(appWallet?.info?.network || "mutinynet").toLowerCase();
    const isMainnet = net === "bitcoin" || net === "mainnet";
    const showBoltzLn = isMainnet && !isVault;
    $("recv-ln-section").classList.toggle("hidden", !showBoltzLn);
    if (showBoltzLn) loadLightningFeeHint();
    $("recv-ark-section").classList.toggle("hidden", isVault);
    if (isStable) {
      startStableAutoReceive();
    } else {
      stopStableAutoReceive();
      $("stable-recv-banner").classList.add("hidden");
    }
    const slot = $(isVault ? "vault-drawer-slot" : isStable ? "stable-drawer-slot" : "spending-drawer-slot");
    if (slot) slot.appendChild(panel);
    panel.classList.remove("hidden");
    renderReceiveQr();
    // Boltz Lightning VHTLC is only shown on Bitcoin mainnet (handled above)
  }

  $("deposit-toggle").onclick = () => openReceivePanel("spending");
  $("vault-recv-toggle").onclick = () => openReceivePanel("vault");
  $("stable-recv-toggle").onclick = () => openReceivePanel("stable");

  function updateVaultPanelUi() {
    const isToArk = vaultDirection === "vault-to-ark";
    $("vault-to-ark-btn").className = `btn ${isToArk ? "primary" : "secondary"} small`;
    $("ark-to-vault-btn").className = `btn ${!isToArk ? "primary" : "secondary"} small`;
    $("vault-dir-pill").textContent = isToArk ? "Vault → Spending" : "Spending → Vault";
    $("vault-dir-note").textContent = isToArk
      ? `Available in Vault (L1): ${lastVaultSats.toLocaleString()} sats. Moves to Arkade Spending (auto-credited after 1 block).`
      : `Available in Spending (Arkade): ${lastAvailSats.toLocaleString()} sats. Offboards to your pure L1 Bitcoin Vault (0 timelock).`;
    const sats = Number($("vault-sats-input").value || 0);
    const sp = spots[activeCurrency] || spots.USD || 0;
    $("vault-fiat-est").textContent =
      sats > 0 && sp > 0 ? `≈ ${fmtFiat((sats / 1e8) * sp, activeCurrency)}` : "";
  }

  document.querySelectorAll("[data-close-panel]").forEach((btn) => {
    btn.onclick = () => {
      const targetId = btn.getAttribute("data-close-panel");
      if (targetId && $(targetId)) $(targetId).classList.add("hidden");
      if (targetId === "orderbook-drawer") renderOrderBook();
    };
  });

  function setSectionOpen(bodyId, open) {
    const body = $(bodyId);
    const head = document.querySelector(`[data-collapse="${bodyId}"]`);
    if (!body) return;
    body.classList.toggle("hidden", !open);
    head?.classList.toggle("open", open);
  }

  function toggleSection(bodyId) {
    const body = $(bodyId);
    if (!body) return false;
    const willOpen = body.classList.contains("hidden");
    setSectionOpen(bodyId, willOpen);
    return willOpen;
  }

  document.querySelectorAll("[data-collapse]").forEach((head) => {
    head.onclick = () => toggleSection(head.getAttribute("data-collapse"));
  });

  $("btn-to-fiat").onclick = () => {
    const opened = toggleSection("lock-body");
    if (opened) {
      $("lock-card")?.scrollIntoView({ behavior: "smooth", block: "center" });
      $("usd-input")?.focus();
    }
  };
  $("btn-to-sats").onclick = () => {
    const opened = toggleSection("positions-body");
    if (opened) {
      $("positions-card")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };
  if ($("long-manage-btn")) {
    $("long-manage-btn").onclick = () => {
      setSectionOpen("positions-body", true);
      $("positions-card")?.scrollIntoView({ behavior: "smooth", block: "start" });
    };
  }

  function openVaultPanel(direction) {
    const panel = $("vault-panel");
    if (!panel.classList.contains("hidden") && vaultDirection === direction) {
      panel.classList.add("hidden");
      return;
    }
    vaultDirection = direction;
    vaultIsMax = false;
    $("vault-sats-input").value = "";
    $("deposit-panel").classList.add("hidden");
    $("send-panel").classList.add("hidden");
    const bridgeSlot = $("bridge-drawer-slot");
    if (bridgeSlot) bridgeSlot.appendChild(panel);
    panel.classList.remove("hidden");
    updateVaultPanelUi();
  }

  $("btn-vault-up").onclick = () => openVaultPanel("vault-to-ark");
  $("btn-vault-down").onclick = () => openVaultPanel("ark-to-vault");
  $("vault-cancel-btn").onclick = () => $("vault-panel").classList.add("hidden");
  $("vault-to-ark-btn").onclick = () => {
    vaultDirection = "vault-to-ark";
    vaultIsMax = false;
    $("vault-sats-input").value = "";
    updateVaultPanelUi();
  };
  $("ark-to-vault-btn").onclick = () => {
    vaultDirection = "ark-to-vault";
    vaultIsMax = false;
    $("vault-sats-input").value = "";
    updateVaultPanelUi();
  };
  $("vault-sats-input").oninput = () => {
    vaultIsMax = false;
    updateVaultPanelUi();
  };
  document.querySelectorAll(".vault-pct").forEach((btn) => {
    btn.onclick = () => {
      const pct = Number(btn.getAttribute("data-vpct"));
      const src = vaultDirection === "vault-to-ark" ? lastVaultSats : lastAvailSats;
      vaultIsMax = pct >= 1 && vaultDirection === "vault-to-ark";
      const val = Math.floor(src * pct);
      $("vault-sats-input").value = val > 0 ? val : "";
      updateVaultPanelUi();
    };
  });
  $("vault-submit-btn").onclick = async () => {
    const sats = Math.floor(Number($("vault-sats-input").value || 0));
    const isToArk = vaultDirection === "vault-to-ark";
    const src = isToArk ? lastVaultSats : lastAvailSats;
    if (!vaultIsMax && (sats <= 0 || sats > src)) {
      showToast(`Enter an amount between 600 and ${src.toLocaleString()} sats`, 4000);
      return;
    }
    const btn = $("vault-submit-btn");
    btn.disabled = true;
    btn.textContent = isToArk ? "Broadcasting L1 tx…" : "Moving to L1 Vault…";
    try {
      if (isToArk) {
        const res = await appWallet.moveVaultToArkade(vaultIsMax ? "max" : sats);
        showToast(
          `Moved ${res.amountSats.toLocaleString()} sats toward Spending (fee ${res.feeSats} sats · auto-credited after 1 conf)`,
          5500
        );
      } else {
        const txid = await appWallet.moveArkadeToVault(sats, (ev) => {
          if (ev?.type) btn.textContent = `Batch: ${ev.type}`;
        });
        showToast(`Moved ${sats.toLocaleString()} sats to Bitcoin Vault L1 (${String(txid).slice(0, 10)}…)`, 5500);
      }
      $("vault-sats-input").value = "";
      vaultIsMax = false;
      $("vault-panel").classList.add("hidden");
      await refresh();
    } catch (e) {
      showToast(`Transfer failed: ${e.message}`, 5000);
    } finally {
      btn.disabled = false;
      btn.textContent = "Transfer Now";
    }
  };
  document.querySelectorAll(".ln-preset").forEach((btn) => {
    btn.onclick = () => {
      $("ln-amount-input").value = btn.getAttribute("data-ln-sats");
    };
  });
  $("ln-create-btn").onclick = async () => {
    const sats = Math.floor(Number($("ln-amount-input").value || 0));
    if (sats <= 0) {
      showToast("Enter an amount in sats");
      return;
    }
    const btn = $("ln-create-btn");
    btn.disabled = true;
    btn.textContent = "Creating…";
    try {
      const res = await appWallet.createLightningInvoice(sats);
      activeLnInvoice = res.invoice;
      activeLnAmountSats = sats;
      $("ln-invoice-text").textContent = res.invoice;
      $("ln-invoice-box").classList.remove("hidden");
      $("ln-invoice-status").textContent = `⏳ Waiting for payment of ${sats.toLocaleString()} sats…`;
      renderReceiveQr();
      showToast("Lightning invoice added to Unified QR — auto-claims when paid!");

      if (activeLnUnsub) {
        try { activeLnUnsub(); } catch {}
        activeLnUnsub = null;
      }
      const swaps = await appWallet.getSwaps();
      const mgr = swaps.getSwapManager?.();
      if (mgr && res.pendingSwap?.id) {
        activeLnUnsub = mgr.subscribeToSwapUpdates(res.pendingSwap.id, async (swap) => {
          const st = swap?.status || "";
          $("ln-invoice-status").textContent = `Swap status: ${st}`;
          if (st === "invoice.settled" || st === "transaction.claimed") {
            $("ln-invoice-status").textContent = `✅ Paid! +${sats.toLocaleString()} sats added to Available BTC`;
            showToast(`⚡ Received +${sats.toLocaleString()} sats via Lightning!`);
            await refresh();
          }
        });
      }
    } catch (e) {
      showToast(`Lightning invoice failed: ${e.message}`, 5000);
    } finally {
      btn.disabled = false;
      btn.textContent = "Create Invoice";
    }
  };
  function pickPositionsToLiquidate(neededExtraSats) {
    const nowSecs = Math.floor(Date.now() / 1000);
    const openStable = Object.values(loadPositions())
      .filter((p) => p.status === "open" && p.side !== "long")
      .map((p) => {
        const termSecs = Number(p.termSecs || 86_400);
        const startTs = Number(p.lastRolledAt || p.openedAt || nowSecs);
        const secsLeft = startTs + termSecs - nowSecs;
        const expiringSoon = secsLeft <= 4 * 3600 ? 0 : 1; // priority 0 = expiring within 4h or expired
        const aprBps = Number(p.fundingRateBpsPerDay ?? 3);
        const pCur = (p.currency || "USD").toUpperCase();
        const pSpot = spots[pCur] || spots.USD || p.openSpotPrice || p.openSpotUsd || 60000;
        const estSats = estimatePositionSats(p, pSpot, computeAccruedInterestUsd(p));
        return { pos: p, expiringSoon, secsLeft, aprBps, estSats };
      })
      .sort((a, b) => {
        if (a.expiringSoon !== b.expiringSoon) return a.expiringSoon - b.expiringSoon;
        if (a.aprBps !== b.aprBps) return a.aprBps - b.aprBps; // lowest APR first
        return a.secsLeft - b.secsLeft; // soonest-expiring tie-breaker
      });

    const chosen = [];
    let acc = 0;
    for (const item of openStable) {
      if (acc >= neededExtraSats) break;
      chosen.push(item);
      acc += item.estSats;
    }
    return chosen;
  }

  function openSendPanel(source) {
    const panel = $("send-panel");
    if (!panel.classList.contains("hidden") && sendSource === source) {
      panel.classList.add("hidden");
      return;
    }
    sendSource = source;
    sendIsMax = false;
    $("deposit-panel").classList.add("hidden");
    $("vault-panel").classList.add("hidden");
    stopStableAutoReceive();
    const isVault = source === "vault";
    const isStable = source === "stable";
    $("send-heading").textContent = isVault
      ? "Send from Bitcoin Vault (Onchain L1)"
      : isStable
      ? `Send from Stable ${activeCurrency}`
      : "Send from Spending";
    $("send-addr-label").innerHTML = isVault
      ? "Recipient Bitcoin L1 Address (<code>tb1…</code> or <code>bitcoin:…</code>)"
      : "Recipient (<code>bitcoin:…</code> BIP-21, <code>lntbs…</code> Lightning, <code>tark1…</code> instant, or <code>tb1…</code> L1)";
    $("send-addr-input").placeholder = isVault ? "tb1… or bitcoin:…" : "bitcoin:…, lntbs…, tark1… or tb1…";
    const satsInp = $("send-sats-input");
    satsInp.value = "";
    satsInp.readOnly = false;
    if (isStable) {
      $("send-amt-label").textContent = `Amount (${activeCurrency})`;
      satsInp.step = "0.01";
      satsInp.min = "0.10";
      satsInp.placeholder = "e.g. 2.50";
    } else {
      $("send-amt-label").textContent = "Amount (sats)";
      satsInp.step = "100";
      satsInp.min = "350";
      satsInp.placeholder = "e.g. 2000";
    }
    $("stable-relock-wrap").classList.toggle("hidden", !isStable);
    const slot = $(isVault ? "vault-drawer-slot" : isStable ? "stable-drawer-slot" : "spending-drawer-slot");
    if (slot) slot.appendChild(panel);
    panel.classList.remove("hidden");
    updateSendUi();
  }

  $("send-toggle").onclick = () => openSendPanel("spending");
  $("vault-send-toggle").onclick = () => openSendPanel("vault");
  $("stable-send-toggle").onclick = () => openSendPanel("stable");
  $("send-cancel-btn").onclick = () => $("send-panel").classList.add("hidden");
  $("send-addr-input").oninput = updateSendUi;
  $("send-sats-input").oninput = () => {
    sendIsMax = false;
    updateSendUi();
  };

  document.querySelectorAll(".send-pct").forEach((btn) => {
    btn.onclick = () => {
      if ($("send-sats-input").readOnly) return;
      const pct = Number(btn.getAttribute("data-pct"));
      if (sendSource === "stable") {
        const sp = spots[activeCurrency] || spots.USD || 0;
        const spendingFiat = sp > 0 ? (lastAvailSats / 1e8) * sp : 0;
        const totalFiat = lastPeggedFiat + spendingFiat;
        const val = totalFiat * pct;
        $("send-sats-input").value = val > 0 ? val.toFixed(2) : "";
      } else {
        const srcBal = sendSource === "vault" ? lastVaultSats : lastAvailSats;
        sendIsMax = sendSource === "vault" && pct >= 1;
        const val = Math.floor(srcBal * pct);
        $("send-sats-input").value = val > 0 ? val : "";
      }
      updateSendUi();
    };
  });

  $("send-submit-btn").onclick = async () => {
    const addr = $("send-addr-input").value.trim();
    const sats = getSendAmountSats();
    const info = detectSendMode(addr);
    const targetAddr = info.target || addr;
    if (info.mode !== "ark" && info.mode !== "l1" && info.mode !== "ln" && info.mode !== "vault-l1") {
      showToast(
        sendSource === "vault"
          ? "Enter a valid Bitcoin L1 address (tb1…)"
          : "Enter a valid BIP-21 URI, Lightning invoice, tark1… (Arkade), or tb1… (Bitcoin L1) address",
        4000
      );
      return;
    }
    const maxBal =
      sendSource === "vault"
        ? lastVaultSats
        : sendSource === "stable"
        ? lastPeggedSats + lastAvailSats
        : lastAvailSats;
    if (info.mode !== "ln" && !sendIsMax && (sats <= 0 || sats > maxBal)) {
      showToast(`Enter an amount between 1 and ${maxBal.toLocaleString()} sats`, 4000);
      return;
    }
    const btn = $("send-submit-btn");
    btn.disabled = true;
    try {
      let liquidatedSats = 0;
      if (sendSource === "stable") {
        let neededSats = sats;
        if (info.mode === "ln") {
          const dec = appWallet.decodeLightningInvoice(targetAddr);
          neededSats = Math.ceil((dec.amountSats || sats) * 1.01); // 1% buffer for Boltz LN fee
        }
        const curBal = Number((await appWallet.getBalance()).available || 0);
        if (neededSats > curBal) {
          const deficit = neededSats - curBal;
          const toClose = pickPositionsToLiquidate(deficit);
          if (toClose.length === 0) throw new Error("No open Stable positions to liquidate");
          for (let i = 0; i < toClose.length; i++) {
            btn.textContent = `Closing Stable pos ${i + 1}/${toClose.length}…`;
            const closed = await appWallet.closePosition(toClose[i].pos.positionId);
            liquidatedSats += Number(closed.userPayoutSats || 0);
          }
        }
      }

      btn.textContent =
        info.mode === "vault-l1"
          ? "Broadcasting L1 tx…"
          : info.mode === "ln"
          ? "Paying Lightning…"
          : info.mode === "ark"
          ? "Sending on Arkade…"
          : "Sending to Bitcoin L1…";

      if (info.mode === "vault-l1") {
        const res = await appWallet.sendFromVault(targetAddr, sendIsMax ? "max" : sats);
        showToast(
          `Sent ${res.amountSats.toLocaleString()} sats from Vault L1 (fee ${res.feeSats} sats · ${res.txid.slice(0, 10)}…)`,
          5500
        );
      } else if (info.mode === "ln") {
        const res = await appWallet.payLightningInvoice(targetAddr);
        showToast(`⚡ Lightning invoice paid! (${String(res.txid || res.preimage || "").slice(0, 10)}…)`, 5000);
      } else {
        const txid =
          info.mode === "ark"
            ? await appWallet.sendArk(targetAddr, sats)
            : await appWallet.offboardToL1(targetAddr, sats, (ev) => {
                if (ev?.type) btn.textContent = `Batch: ${ev.type}`;
              });
        showToast(
          info.mode === "ark"
            ? `Sent ${sats.toLocaleString()} sats on Arkade (${String(txid).slice(0, 10)}…)`
            : `Sent ${sats.toLocaleString()} sats to Bitcoin L1 (${String(txid).slice(0, 10)}…)`
        );
      }

      // Optionally re-lock leftover change from liquidated Stable positions back into Stable fiat
      if (sendSource === "stable" && liquidatedSats > 0 && $("stable-relock-check")?.checked) {
        const changeSats = Math.max(0, liquidatedSats - sats);
        const cur = activeCurrency;
        const sp = spots[cur] || spots.USD || 60000;
        const changeFiat = Number(((changeSats / 1e8) * sp).toFixed(2));
        if (changeFiat >= 1) {
          btn.textContent = `Re-locking ${fmtFiat(changeFiat, cur)} change…`;
          const selected = getSelectedLp();
          await appWallet.openPosition(changeFiat, selected, selected.lpName, cur, "short").catch(() => {});
          showToast(`Sent payment & re-locked ${fmtFiat(changeFiat, cur)} change into Stable ${cur}`, 5500);
        }
      }

      $("send-addr-input").value = "";
      $("send-sats-input").value = "";
      $("send-sats-input").readOnly = false;
      sendIsMax = false;
      $("send-panel").classList.add("hidden");
      await refresh();
    } catch (e) {
      showToast(`Send failed: ${e.message}`, 5000);
    } finally {
      btn.disabled = false;
      btn.textContent = "Send Now";
    }
  };
  $("settings-btn").onclick = () => {
    const panel = $("settings-panel");
    const willOpen = panel.classList.contains("hidden");
    panel.classList.toggle("hidden");
    if (willOpen) {
      panel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };
  $("nostr-pill").onclick = () => {
    const panel = $("settings-panel");
    panel.classList.remove("hidden");
    $("advanced-settings").open = true;
    refreshNostracleReputation();
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  $("advanced-settings").ontoggle = () => {
    if ($("advanced-settings").open) refreshNostracleReputation();
  };
  $("refresh-btn").onclick = async () => {
    await verifyOrderBookPof(true);
    renderOrderBook();
    refresh();
    fetchQuoteUi();
  };
  $("ob-auto-btn").onclick = () => {
    manualLpPubkey = null;
    renderOrderBook();
    refresh();
    fetchQuoteUi();
    showToast("Auto-selecting best LP from orderbook");
  };

  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.onclick = async () => {
      const txt = $(btn.getAttribute("data-copy")).textContent;
      await navigator.clipboard.writeText(txt);
      showToast("Copied to clipboard");
    };
  });

  document.querySelectorAll(".chip[data-usd]").forEach((chip) => {
    chip.onclick = () => {
      document.querySelectorAll(".chip[data-usd]").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      $("usd-input").value =
        activeSide === "long" ? chip.getAttribute("data-sats") || "5000" : chip.getAttribute("data-usd");
      renderOrderBook();
      fetchQuoteUi();
    };
  });

  $("usd-input").onchange = () => {
    renderOrderBook();
    fetchQuoteUi();
  };

  document.querySelectorAll(".cur-btn").forEach((btn) => {
    btn.onclick = () => {
      activeCurrency = btn.getAttribute("data-cur") || "USD";
      manualLpPubkey = null;
      applyCurrencyUi();
      renderOrderBook();
      tickInterest();
      fetchQuoteUi();
    };
  });

  let p2pSide = "short"; // independent side for P2P Order Book maker form

  function getP2pNotionalFiat(spotPrice) {
    const raw = Number($("p2p-amt-input")?.value || 0);
    if (p2pSide === "long") {
      // Input is in sats for 2x Long BTC margin -> convert to fiat notional
      return spotPrice > 0 ? (raw / 1e8) * spotPrice : 0;
    }
    return raw;
  }

  function getBestMarketImplied(termDays) {
    const cur = activeCurrency;
    const sp = spots[cur] || spots.USD || 60000;
    const amt = getP2pNotionalFiat(sp) || 5;
    const lpOffers = orderBook
      .getOffers({ pair: activePair(), notionalFiat: amt })
      .filter((o) => o.makerType !== "p2p");
    const best = lpOffers[0];
    const lpName = best?.lpName || "Market";
    const lpSpread = Number(best?.spreadBps ?? 10);
    const lpFunding = Number(best?.fundingRateBpsPerDay ?? 3);

    if (p2pSide === "short") {
      // Stable user (1x Short BTC): earns funding over term minus entry spread
      const netBps = lpFunding * termDays - lpSpread;
      const bestPrice = Math.round(sp * (1 + netBps / 10_000));
      return { spot: sp, bestPrice, netBps, lpName, cur };
    } else {
      // 2x Long BTC user: pays spread + funding over term
      const costBps = lpSpread + lpFunding * termDays;
      const bestPrice = Math.round(sp * (1 + costBps / 10_000));
      return { spot: sp, bestPrice, netBps: -costBps, lpName, cur };
    }
  }

  function applyP2pSideUi() {
    const cur = activeCurrency;
    const sp = spots[cur] || spots.USD || 60000;
    const isLong = p2pSide === "long";
    $("p2p-side-short").textContent = `🛡 Stable ${cur} (1× Short BTC)`;
    $("p2p-side-short").classList.toggle("active", !isLong);
    $("p2p-side-long").classList.toggle("active", isLong);
    const raw = Number($("p2p-amt-input")?.value || 0);
    if (isLong) {
      const approxFiat = sp > 0 && raw > 0 ? ` (≈ ${fmtFiat((raw / 1e8) * sp, cur)})` : "";
      $("p2p-amt-label").textContent = `Margin (sats)${approxFiat}`;
      $("p2p-amt-input").step = "1000";
      $("p2p-amt-input").min = "1000";
    } else {
      const approxSats = sp > 0 && raw > 0 ? ` (≈ ${Math.round((raw / sp) * 1e8).toLocaleString()} sats)` : "";
      $("p2p-amt-label").textContent = `Stable Amount (${cur})${approxSats}`;
      $("p2p-amt-input").step = "1";
      $("p2p-amt-input").min = "1";
    }
    $("p2p-side-explain").innerHTML = isLong
      ? `<strong>🚀 2× Long BTC (Leveraged):</strong> Put up BTC sats as margin for 2× upside (liq. ~50% below entry). Matched with a Stable ${cur} peer.`
      : `<strong>🛡 Stable ${cur} (1× Short BTC):</strong> Lock fixed ${cur} value &amp; earn yield regardless of BTC price. Matched with a 2× Long BTC peer.`;
  }

  function applyP2pPreset(preset) {
    applyP2pSideUi();
    const termDays = Number($("p2p-term-select")?.value || 1);
    const mkt = getBestMarketImplied(termDays);
    const stepBps = preset === "beat" ? 5 : preset === "better" ? 10 : 0;
    let deltaSign = 0;
    if (preset === "beat") deltaSign = p2pSide === "short" ? -1 : 1;
    if (preset === "better") deltaSign = p2pSide === "short" ? 1 : -1;
    const price = Math.round(mkt.bestPrice * (1 + (deltaSign * stepBps) / 10_000));
    $("p2p-price-input").value = price;
    document.querySelectorAll(".p2p-preset").forEach((b) => {
      b.classList.toggle("active", b.getAttribute("data-p2p-preset") === preset);
    });
    updateP2pPricingUi();
  }

  function updateP2pPricingUi() {
    const form = $("p2p-order-form");
    if (!form) return;
    applyP2pSideUi();
    const termDays = Math.max(1, Number($("p2p-term-select")?.value || 1));
    const mkt = getBestMarketImplied(termDays);
    const amt = getP2pNotionalFiat(mkt.spot);
    const sym = curSym(mkt.cur);
    $("p2p-price-label").textContent = `Your Implied Entry Price (${mkt.cur} · ${termDays}d term)`;
    $("p2p-market-ref").innerHTML =
      `Spot: <strong>${sym}${mkt.spot.toLocaleString()}</strong> · Best Market (${mkt.lpName}, ${termDays}d): <strong>${sym}${mkt.bestPrice.toLocaleString()}</strong>`;

    let userPrice = Number($("p2p-price-input").value || 0);
    if (!userPrice || userPrice <= 0) {
      userPrice = mkt.bestPrice;
      $("p2p-price-input").value = userPrice;
    }

    const rawDiffBps = ((userPrice - mkt.bestPrice) / mkt.spot) * 10_000;
    const attractivenessBps = p2pSide === "short" ? -rawDiffBps : rawDiffBps;

    const vsSpotBps = ((userPrice - mkt.spot) / mkt.spot) * 10_000;
    const makerTotalBps = p2pSide === "short" ? vsSpotBps : -vsSpotBps;
    const makerBpsPerDay = makerTotalBps / termDays;
    const netFiat = amt * (makerTotalBps / 10_000);
    const netSign = netFiat >= 0 ? "+" : "-";
    const pctStr = `${makerTotalBps >= 0 ? "+" : ""}${(makerTotalBps / 100).toFixed(2)}%`;

    const guide = $("p2p-guidance");
    const attrPct = (Math.abs(attractivenessBps) / 100).toFixed(2);
    const aprLabel = fmtYield(makerBpsPerDay);
    if (attractivenessBps >= 2) {
      guide.className = "roll-hint good";
      guide.innerHTML =
        `🟢 <strong>More attractive than ${mkt.lpName}</strong> (+${attrPct}% better for counterparty) — likely to match quickly!<br/>` +
        `<span class="muted">Net over ${termDays}d: ${netSign}${sym}${Math.abs(netFiat).toFixed(3)} (${pctStr} · ${aprLabel})</span>`;
    } else if (attractivenessBps <= -2) {
      guide.className = "roll-hint";
      guide.innerHTML =
        `🟠 <strong>Less attractive than ${mkt.lpName}</strong> (${attrPct}% better for you) — may wait longer to fill.<br/>` +
        `<span class="muted">Net over ${termDays}d: ${netSign}${sym}${Math.abs(netFiat).toFixed(3)} (${pctStr} · ${aprLabel})</span>`;
    } else {
      guide.className = "roll-hint";
      guide.innerHTML =
        `🟡 <strong>In line with best market offer</strong> (${mkt.lpName}) — fair market price.<br/>` +
        `<span class="muted">Net over ${termDays}d: ${netSign}${sym}${Math.abs(netFiat).toFixed(3)} (${pctStr} · ${aprLabel})</span>`;
    }
    return { makerBpsPerDay, termSecs: termDays * 86_400, spot: mkt.spot };
  }

  document.querySelectorAll(".side-btn[data-side]").forEach((btn) => {
    btn.onclick = () => {
      const next = btn.getAttribute("data-side") === "long" ? "long" : "short";
      if (next !== activeSide) {
        const sp = spots[activeCurrency] || spots.USD || 60000;
        const curVal = Number($("usd-input").value || 0);
        if (next === "long") {
          $("usd-input").value = sp > 0 && curVal > 0 ? Math.max(1000, Math.round((curVal / sp) * 1e8)) : 5000;
        } else {
          $("usd-input").value = sp > 0 && curVal > 0 ? Math.max(1, Math.round((curVal / 1e8) * sp)) : 2;
        }
      }
      activeSide = next;
      applyCurrencyUi();
      renderOrderBook();
      fetchQuoteUi();
    };
  });

  document.querySelectorAll("[data-p2p-side]").forEach((btn) => {
    btn.onclick = () => {
      const next = btn.getAttribute("data-p2p-side") === "long" ? "long" : "short";
      if (next !== p2pSide) {
        const sp = spots[activeCurrency] || spots.USD || 60000;
        const curVal = Number($("p2p-amt-input").value || 0);
        if (next === "long") {
          $("p2p-amt-input").value = sp > 0 && curVal > 0 ? Math.max(1000, Math.round((curVal / sp) * 1e8)) : 5000;
        } else {
          $("p2p-amt-input").value = sp > 0 && curVal > 0 ? Math.max(1, Math.round((curVal / 1e8) * sp)) : 5;
        }
      }
      p2pSide = next;
      applyP2pPreset("match");
    };
  });

  $("p2p-order-toggle").onclick = () => {
    const form = $("p2p-order-form");
    const wasHidden = form.classList.contains("hidden");
    form.classList.toggle("hidden");
    if (wasHidden) {
      const sp = spots[activeCurrency] || spots.USD || 60000;
      const usdVal = Number($("usd-input").value || 5);
      $("p2p-amt-input").value = p2pSide === "long" ? Math.max(1000, Math.round((usdVal / sp) * 1e8)) : usdVal;
      applyP2pPreset("match");
    }
  };
  $("p2p-amt-input").oninput = () => updateP2pPricingUi();
  $("p2p-term-select").onchange = () => applyP2pPreset("match");
  $("p2p-price-input").oninput = () => {
    document.querySelectorAll(".p2p-preset").forEach((b) => b.classList.remove("active"));
    updateP2pPricingUi();
  };
  document.querySelectorAll(".p2p-preset").forEach((btn) => {
    btn.onclick = () => applyP2pPreset(btn.getAttribute("data-p2p-preset"));
  });

  $("p2p-publish-btn").onclick = async () => {
    const expirySecs = Number($("p2p-expiry-select").value || 900);
    const cur = activeCurrency;
    const pricing = updateP2pPricingUi();
    const amt = Number(getP2pNotionalFiat(pricing.spot).toFixed(2));
    if (amt <= 0) {
      showToast(p2pSide === "long" ? "Enter a valid margin in sats" : "Enter a valid fiat amount");
      return;
    }
    const btn = $("p2p-publish-btn");
    btn.disabled = true;
    btn.textContent = "Publishing to Order Book…";
    try {
      const res = await appWallet.postP2pOrder({
        side: p2pSide,
        currency: cur,
        notional: amt,
        spotPrice: pricing.spot,
        fundingRateBpsPerDay: Number(pricing.makerBpsPerDay.toFixed(2)),
        termSecs: pricing.termSecs,
        expirySecs,
        displayName: nostrProfile?.name || "",
        onOrderFilled: async (pos) => {
          renderMyP2pOrderBanner();
          showToast(
            `🎉 Your P2P order matched! Opened ${fmtFiat(pos.notional, pos.currency)} (${pos.side === "long" ? "2× Long BTC" : `Stable ${pos.currency}`})`,
            6000
          );
          await refresh();
        },
      });
      $("p2p-order-form").classList.add("hidden");
      renderMyP2pOrderBanner();
      showToast(`P2P Order live on ${res.accepted}/${res.total} relays — keep tab open to match!`, 5000);
    } catch (e) {
      showToast(`Post order failed: ${e.message}`, 5000);
    } finally {
      btn.disabled = false;
      btn.textContent = "Publish P2P Order";
    }
  };

  $("ob-toggle-btn").onclick = () => {
    $("orderbook-drawer").classList.toggle("hidden");
    renderOrderBook();
  };

  $("open-btn").onclick = async () => {
    const amt = getActiveTradeNotionalFiat();
    if (amt <= 0) return;
    const selected = getSelectedLp();
    const cur = activeCurrency;
    const side = activeSide;
    $("open-btn").disabled = true;
    $("open-btn").textContent = "Signing & Opening…";
    try {
      const pos = await appWallet.openPosition(amt, selected, selected.lpName, cur, side);
      showToast(
        side === "long"
          ? `Opened 2× Long BTC (${fmtFiat(pos.notional ?? pos.notionalUsd, cur)} margin) via ${pos.lpName}`
          : `Locked ${fmtFiat(pos.notional ?? pos.notionalUsd, cur)} ${cur} via ${pos.lpName}`
      );
      await refresh();
    } catch (e) {
      showToast(`Open failed: ${e.message}`, 5000);
    } finally {
      $("open-btn").disabled = false;
      applyCurrencyUi();
    }
  };

  $("save-relays-btn").onclick = () => {
    try {
      const saved = setNostrRelays($("relays-input").value);
      $("relays-input").value = saved.join(", ");
      startOrderBookSubscription();
      showToast(`Subscribed to ${saved.length} Nostr relays`);
    } catch (e) {
      showToast(e.message, 4000);
    }
  };

  $("save-wt-btn").onclick = () => {
    try {
      const saved = setWatchtowerPubkey($("wt-pubkey-input").value);
      $("wt-pubkey-input").value = saved;
      showToast(saved ? "Watchtower pubkey saved" : "Watchtower pubkey cleared");
    } catch (e) {
      showToast(e.message, 4000);
    }
  };

  $("quorum-select").onchange = () => {
    const saved = setQuorumPreset($("quorum-select").value);
    renderNostracles();
    showToast(`Default Nostracle quorum set to ${saved}`);
  };

  $("add-nostracle-btn").onclick = () => {
    const keyVal = $("custom-nostracle-key").value;
    const nameVal = $("custom-nostracle-name").value;
    try {
      const added = addCustomNostracle(keyVal, nameVal);
      $("custom-nostracle-key").value = "";
      $("custom-nostracle-name").value = "";
      renderNostracles();
      refreshNostracleReputation();
      showToast(`Added custom Nostracle: ${added.name}`);
    } catch (e) {
      showToast(e.message, 4500);
    }
  };

  $("reveal-backup-btn").onclick = () => {
    const inp = $("backup-key-input");
    const hidden = inp.type === "password";
    inp.type = hidden ? "text" : "password";
    $("reveal-backup-btn").textContent = hidden ? "Hide" : "Show";
  };

  $("copy-backup-btn").onclick = async () => {
    const val = $("backup-key-input").value;
    if (!val) return;
    await navigator.clipboard.writeText(val);
    showToast("Backup Key copied — store it offline and keep it private!");
  };

  $("header-nostr-login-btn").onclick = () => {
    if (hasNip07Extension()) {
      $("onboard-nip07-btn")?.click();
    } else {
      $("onboard-nsec-input")?.focus();
    }
  };

  $("onboard-nip07-btn").onclick = async () => {
    const btn = $("onboard-nip07-btn");
    btn.disabled = true;
    btn.textContent = "Connecting Nostr Extension…";
    try {
      const res = await loginWithNip07Extension(getNostrRelays());
      showToast(
        res.createdNew
          ? `⚡ Connected ${res.npub.slice(0, 12)}… & saved encrypted portable wallet seed to Nostr!`
          : `⚡ Restored portable Arkade + L1 Vault wallet for ${res.npub.slice(0, 12)}…!`,
        4500
      );
      setTimeout(() => location.reload(), 700);
    } catch (e) {
      showToast(`Extension login failed: ${e.message}`, 5500);
      btn.disabled = false;
      btn.textContent = "⚡ Login with Nostr Extension (Alby / nos2x)";
    }
  };

  $("onboard-nsec-btn").onclick = async () => {
    const raw = $("onboard-nsec-input").value.trim();
    if (!raw) {
      showToast("Paste your nsec1… or 64-char hex Backup Key first");
      return;
    }
    const btn = $("onboard-nsec-btn");
    btn.disabled = true;
    btn.textContent = "Restoring…";
    try {
      const res = await restoreFromBackupKey(raw);
      $("onboard-nsec-input").value = "";
      showToast(
        res.restoredCloudSeed
          ? "Restored portable encrypted seed from Nostr — loading wallet…"
          : "Wallet restored from nsec — loading wallet…"
      );
      setTimeout(() => location.reload(), 600);
    } catch (e) {
      showToast(`Invalid Backup Key: ${e.message}`, 4500);
      btn.disabled = false;
      btn.textContent = "Login";
    }
  };

  $("onboard-create-btn").onclick = () => {
    const { nostrAccount } = createFreshNostrWallet();
    $("onboard-choices").classList.add("hidden");
    $("onboard-created-step").classList.remove("hidden");
    $("onboard-new-nsec").value = nostrAccount.nsec;
    showToast("✨ New Nostr identity created — copy your nsec1… backup key!");
  };

  $("onboard-copy-nsec-btn").onclick = async () => {
    const val = $("onboard-new-nsec").value;
    if (!val) return;
    await navigator.clipboard.writeText(val);
    showToast("Secret nsec1… copied — store it offline and keep it private!");
  };

  $("onboard-enter-btn").onclick = () => {
    location.reload();
  };

  $("logout-btn").onclick = async () => {
    const isNip07 = appWallet?.authIdentity?.mode === "nip07";
    const ok = confirm(
      isNip07
        ? "Log out of Nostr Extension?\nYour encrypted wallet seed remains safely stored on Nostr for next login."
        : "Log out and clear this browser's wallet key?\n\nMake sure you have copied your Backup Key (nsec1…) first if you hold any funds!"
    );
    if (!ok) return;
    try {
      await appWallet?.wallet?.clear?.();
      await appWallet?.wallet?.dispose?.();
    } catch {}
    try {
      if (typeof indexedDB !== "undefined" && indexedDB.databases) {
        const dbs = await indexedDB.databases();
        for (const db of dbs) {
          if (db?.name) indexedDB.deleteDatabase(db.name);
        }
      }
    } catch {}
    clearAllWalletAuth();
    showToast("Logged out — returning to sign-in…");
    setTimeout(() => location.reload(), 400);
  };

  $("publish-profile-btn").onclick = async () => {
    const name = $("nostr-name-input").value.trim();
    const picture = $("nostr-pic-input").value.trim();
    if (!name && !picture) {
      showToast("Enter a display name or photo URL first");
      return;
    }
    const btn = $("publish-profile-btn");
    btn.disabled = true;
    btn.textContent = "Saving…";
    try {
      const res = await publishNostrProfile(
        appWallet.authIdentity || appWallet.nostrKey,
        { name, picture },
        getNostrRelays()
      );
      nostrProfile = { ...(nostrProfile || {}), name, username: name, picture };
      renderNostrAccount();
      showToast(`Profile saved to ${res.accepted}/${res.total} relays`);
    } catch (e) {
      showToast(`Save failed: ${e.message}`, 4500);
    } finally {
      btn.disabled = false;
      btn.textContent = "Save";
    }
  };

  $("reveal-key-btn").onclick = () => {
    const inp = $("privkey-input");
    const hidden = inp.type === "password";
    inp.type = hidden ? "text" : "password";
    $("reveal-key-btn").textContent = hidden ? "Hide" : "Show";
  };

  $("copy-key-btn").onclick = async () => {
    const val = $("privkey-input").value;
    if (!val) return;
    await navigator.clipboard.writeText(val);
    showToast("Raw Arkade Spending Key copied (read-only export)");
  };

  renderOrderBook();
  startOrderBookSubscription();

  // Do NOT auto-generate a ghost key before the user chooses how to sign in.
  if (!hasStoredAccount()) {
    $("onboarding-card").classList.remove("hidden");
    $("wallet-main").classList.add("hidden");
    $("refresh-btn").classList.add("hidden");
    $("settings-btn").classList.add("hidden");
    $("header-nostr-login-btn").classList.remove("hidden");
    return;
  }

  $("onboarding-card").classList.add("hidden");
  $("wallet-main").classList.remove("hidden");

  appWallet = await BrowserP2pFiatWallet.create();
  $("privkey-input").value = appWallet.userKey.privHex;
  renderNostrAccount();
  refreshNostrProfile();
  restorePositionsFromNostr()
    .then((res) => {
      if (res?.restoredCount > 0) {
        renderPositions();
        tickInterest();
        showToast(`Restored ${res.restoredCount} position(s) from encrypted Nostr backup`, 5000);
      }
    })
    .catch(() => {});
  await refresh();

  // Mutinynet instant onboarding faucet: run immediately after initial balance check
  // (do NOT wait for orderbook PoF or quote RPC!) so new testers see the pending banner right away.
  (async () => {
    try {
      const net = String(appWallet?.info?.network || "mutinynet").toLowerCase();
      const isMutinynet = net !== "bitcoin" && net !== "mainnet";
      const pubId = (appWallet?.authIdentity?.pubHex || appWallet?.nostrKey?.pubHex || "").toLowerCase();
      const faucetFlag = pubId ? `p2pfiat_faucet_requested_${pubId}` : "";
      const hasOpenPositions = Object.values(loadPositions()).some((p) => p?.status === "open");
      if (
        isMutinynet &&
        faucetFlag &&
        !localStorage.getItem(faucetFlag) &&
        lastAvailSats === 0 &&
        lastVaultSats === 0 &&
        !hasOpenPositions
      ) {
        const banner = $("faucet-pending-banner");
        if (banner) {
          banner.innerHTML =
            "⏳ <strong>Pending 20,000 free Mutinynet testnet sats…</strong> Requesting instant Arkade VTXO from LP-Home.";
          banner.classList.remove("hidden");
        }
        const balNow = await appWallet.getBalance().catch(() => ({ boarding: 0, available: 0 }));
        if (Number(balNow.available || 0) > 0 || Number(balNow.boarding || 0) > 0) {
          banner?.classList.add("hidden");
          return;
        }
        localStorage.setItem(faucetFlag, "1");
        try {
          const res = await appWallet.requestMutinynetFaucet();
          banner?.classList.add("hidden");
          if (res?.ok) {
            showToast("🎉 Received 20,000 free Mutinynet testnet sats — ready to test!", 6000);
            await refresh();
          }
        } catch (err) {
          localStorage.removeItem(faucetFlag);
          if (banner) {
            banner.innerHTML = `⚠ Faucet delayed (${escapeHtml(err?.message || "timeout")}) — <button id="faucet-retry-btn" class="btn small secondary" style="margin-left:6px">Retry 20k sats</button>`;
            $("faucet-retry-btn").onclick = async () => {
              banner.innerHTML = "⏳ <strong>Pending 20,000 free Mutinynet testnet sats…</strong> Retrying…";
              try {
                const r = await appWallet.requestMutinynetFaucet();
                banner.classList.add("hidden");
                if (r?.ok) {
                  localStorage.setItem(faucetFlag, "1");
                  showToast("🎉 Received 20,000 free Mutinynet testnet sats!", 6000);
                  await refresh();
                }
              } catch (e2) {
                banner.innerHTML = `⚠ Faucet error: ${escapeHtml(e2?.message || "retry later")}`;
              }
            };
          }
        }
      }
    } catch {}
  })();

  await verifyOrderBookPof(true);
  await fetchQuoteUi();

  // Smart background VTXO compaction: ONLY settle preconfirmed VTXOs when the unroll chain
  // actually gets deep (>= 12 hops) so normal 1-2 hop users NEVER pay unnecessary Arkade round fees (~40 sats).
  const autoCompactVtxos = async () => {
    try {
      const vtxos = await appWallet.wallet.getVtxos();
      const preconf = (vtxos || []).filter((v) => v?.virtualStatus?.state === "preconfirmed");
      if (preconf.length === 0) return;
      let maxHops = 0;
      for (const v of preconf.slice(0, 3)) {
        try {
          const resp = await appWallet.indexerProvider.getVtxoChain({ txid: v.txid, vout: v.vout });
          const chain = resp?.txs?.length ? resp.txs : resp?.chain || [];
          const hops = chain.filter((c) => !String(c.type).toLowerCase().includes("commitment") && c.type !== 1).length;
          if (hops > maxHops) maxHops = hops;
        } catch {}
      }
      if (maxHops >= 12) {
        await appWallet.settleVtxos();
        showToast(`⚡ Compacted deep VTXO chain (${maxHops} hops → 1 hop · ~40 sats Arkade round fee)`, 5500);
        await refresh();
      }
    } catch {}
  };
  setTimeout(autoCompactVtxos, 30_000);
  setInterval(() => {
    if (document.visibilityState === "visible") autoCompactVtxos();
  }, 30 * 60_000);

  // Battery-friendly 10s local interest ticker (pauses automatically when tab is hidden)
  setInterval(() => {
    if (document.visibilityState === "visible") tickInterest();
  }, 10_000);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") tickInterest();
  });
}

boot();
