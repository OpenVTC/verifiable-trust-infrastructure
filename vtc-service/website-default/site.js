// Default community website — bootstrap shell.
//
// Renders the community profile + health status into the placeholder
// nodes in index.html. When `website.root_dir` is set in the daemon
// config, this script is replaced by the operator's site and never
// runs.

async function fetchJson(url) {
  const r = await fetch(url);
  if (!r.ok) {
    throw new Error(`${url} → ${r.status}`);
  }
  return r.json();
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = text;
  }
}

function setStatus(state, label) {
  const dot = document.getElementById("status-dot");
  const text = document.getElementById("status-label");
  if (dot) {
    dot.classList.remove("ok", "warn", "err");
    if (state) dot.classList.add(state);
  }
  if (text) text.textContent = label;
}

function showMediatorRow(did) {
  const row = document.getElementById("mediator-row");
  if (!row || !did) return;
  setText("mediator-did", did);
  row.hidden = false;
}

function showLogo(url, alt) {
  const img = document.getElementById("community-logo");
  if (!img || !url) return;
  // Drop the alt text in too — community name when available,
  // empty otherwise (the logo is decorative; the page already
  // shows the name as text).
  img.alt = alt ? `${alt} logo` : "";
  // Hide again if the operator's URL 404s, points at a wrong MIME,
  // or is otherwise unloadable — better silent than broken-image.
  img.addEventListener(
    "error",
    () => {
      img.hidden = true;
      console.warn("community logo failed to load", url);
    },
    { once: true },
  );
  img.src = url;
  img.hidden = false;
}

// ── Copy-to-clipboard wiring ───────────────────────────────
//
// Buttons carry `data-copy-target="<id>"`. On click, copy that
// element's textContent, flip the button into a "copied" state for
// COPY_FEEDBACK_MS, then revert. Uses the async Clipboard API where
// available with a textarea-selection fallback for older browsers /
// non-secure contexts.

const COPY_FEEDBACK_MS = 1600;
const copyTimers = new WeakMap();

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  // Fallback for http:// during local dev.
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand("copy");
  } finally {
    document.body.removeChild(ta);
  }
}

function flashCopied(btn) {
  const label = btn.querySelector(".copy-label");
  const original = btn.dataset.originalLabel ?? (label ? label.textContent : "Copy");
  if (!btn.dataset.originalLabel) {
    btn.dataset.originalLabel = original;
  }
  btn.classList.add("copied");
  if (label) label.textContent = "Copied!";
  const prev = copyTimers.get(btn);
  if (prev) clearTimeout(prev);
  copyTimers.set(
    btn,
    setTimeout(() => {
      btn.classList.remove("copied");
      if (label) label.textContent = original;
    }, COPY_FEEDBACK_MS),
  );
}

function wireCopyButtons() {
  for (const btn of document.querySelectorAll("[data-copy-target]")) {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.copyTarget;
      if (!id) return;
      const source = document.getElementById(id);
      const text = source?.textContent?.trim();
      if (!text || text === "…") return;
      try {
        await copyText(text);
        flashCopied(btn);
      } catch (err) {
        console.warn("copy failed", err);
      }
    });
  }
}

async function refresh() {
  // Health probe — small + unauthenticated so it works on a
  // freshly-installed daemon with no auth keys yet. Also the
  // canonical source for the VTC's own DID (post-setup).
  let healthJson = null;
  try {
    healthJson = await fetchJson("/health");
    setText("health-status", `${healthJson.status} (v${healthJson.version})`);
    if (healthJson.vtc_did) {
      setText("community-did", healthJson.vtc_did);
    } else {
      setText("community-did", "(not yet provisioned — run `vtc setup`)");
    }
    // The mediator DID is sourced from `/v1/community/public-profile`
    // below; `/health` no longer carries mediator detail (it's
    // admin-gated infrastructure topology — see P3.7).
    const state = healthJson.status === "ok" ? "ok" : "warn";
    setStatus(state, state === "ok" ? "Service online" : "Degraded");
  } catch (err) {
    setText("health-status", `error: ${err.message}`);
    setText("community-did", `error: ${err.message}`);
    setStatus("err", "Service unreachable");
  }

  // Community profile — best-effort, for the friendly name +
  // description shown in the header. `/v1/community/public-profile`
  // is the unauthenticated read endpoint exposing only the curated
  // public subset (name, description, public URL, mediator DID).
  // On a fresh install the profile row is initialised with empty
  // name + description; operators populate them via the admin UX.
  // Distinguish the cases so the visitor knows whether the daemon
  // is silent (404) or just hasn't been named yet (empty fields).
  try {
    const profile = await fetchJson("/v1/community/public-profile");
    if (profile && typeof profile === "object") {
      if (profile.name) {
        setText("community-name", profile.name);
        document.title = profile.name;
      } else {
        // Profile exists but the operator hasn't set a name. Replace
        // the install-time placeholder copy with something more
        // honest so the page doesn't claim the profile is missing.
        setText("community-name", "Verifiable Trust Community");
        setText(
          "community-description",
          "The operator hasn't set a community name or description yet — they can do that from the admin console.",
        );
      }
      if (profile.description) {
        setText("community-description", profile.description);
      }
      if (profile.logoUrl) {
        showLogo(profile.logoUrl, profile.name);
      }
      // The public-profile endpoint also surfaces the mediator DID
      // so a single fetch is enough; `/health` is a fallback for
      // pre-bootstrap state where the profile isn't initialised yet.
      if (profile.mediatorDid) {
        showMediatorRow(profile.mediatorDid);
      }
    }
  } catch (err) {
    // The default landing page sits in front of every freshly-
    // installed VTC. A 404 here means the profile keyspace is
    // empty (pre-`vtc setup`). Anything else is unexpected — log
    // it so an operator opening DevTools can see what went wrong.
    console.warn("public-profile fetch failed", err);
  }
}

wireCopyButtons();
refresh();
