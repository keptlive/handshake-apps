# Handshake Apps — threat model (normative)

Companion to `HANDSHAKE-APPS.md` v0.1. Where the two disagree, this file
wins. Section references (§) point into HANDSHAKE-APPS.md.

## 1. Assumptions

**Trusted:** the browser main process (mediator), the vault, the registry
panel and its database, the operator's DNSSEC signer, the OS user account.

**Untrusted:** every app — its author, its manifest, its pages and any
server it talks to; every renderer process; all app-supplied strings;
the network between mediator and registry (TLS assumed, but requests are
additionally NIP-98-signed so a TLS-terminating middlebox cannot mint
mutations); any third-party app directory.

**The user:** honest but naive. They will click through anything that looks
routine; consent design must make the *un*-routine look different, and must
bound the damage of a wrong click to the granted scope.

**Assets, in priority order:**
1. Control keys (loss = permanent, unrecoverable name takeover — there is no
   master secret by design; identity-account.js header).
2. Identity anchors: `_hns` / `_atproto` records, NIP-05, PGP/SMIMEA, DANE
   TLSA (corruption = impersonation of the person, not just the site).
3. Delegation: NS/DS (corruption = silent full-zone takeover, DNSSEC break).
4. Ordinary records and published content (corruption = defacement,
   recoverable).
5. The user's portfolio privacy (which names they hold).

## 2. Threats and mitigations

### T1 — Key exfiltration / signing oracle
*A hostile app tries to read a control key, or to get the mediator to sign
attacker-chosen bytes (a NIP-98 event for an arbitrary URL/body, a claim
receipt for a name it doesn't hold, a Nostr event, a wallet transaction).*

- No provider verb accepts raw bytes to sign or returns signatures. The only
  signed artifacts are NIP-98 headers over mediator-built request bodies for
  the four whitelisted endpoints, and claim receipts built by the mediator's
  own `claimIdentity` (§5.3). An app cannot influence a signed byte except
  through schema-validated fields that the mediator embeds into structures
  it built.
- Keys are read from the vault inside the privileged function and go out of
  scope after signing (`bindAtproto` pattern); nothing key-derived crosses
  IPC but signatures over mediator-built messages.
- Renderers run with context isolation; the provider is a preload-exposed
  RPC stub, not an object graph into main.
- Residual risk: a main-process RCE owns the vault. That is the browser's
  existing security boundary, unchanged by this standard; the standard's job
  is to add **no new** path across it, and it adds none.

### T2 — Over-broad capabilities / scope creep
*A manifest requests everything ("all TXT on all names"), or a benign v1
updates to a grabby v2.*

- Capabilities are shapes, not types: every DNS capability names a
  `record_schema` with owner pattern + type + literal value/owner
  discriminator (§4, §6). "All TXT" is not expressible.
- `tlds` + per-name grants: install conveys nothing; each name is granted
  individually by user pick (§8). The provider cannot enumerate ungranted
  names (T13).
- Updates that broaden capabilities or shapes trigger differential
  re-consent pinned to manifest hashes (§8); grants stay on the old hash
  until accepted.
- Review tier (curated directory) exists to reject grabby manifests
  socially before users see them (§7), but is not load-bearing.

### T3 — Identity hijack via managed records
*An app writes `_hns.alice` (rebind the control key), `_atproto.alice`
(steal the Bluesky handle), OPENPGPKEY/SMIMEA (intercept encrypted mail),
or DANE TLSA (break/hijack TLS).*

- No capability grammar reaches these surfaces (§4.2): the mediator refuses
  owner patterns under `MANAGED_PREFIXES`, the managed types, and DANE-owned
  TLSA owners at manifest-validation time (install fails) and again at
  `propose` time.
- Independently, the registry refuses them for **everyone** —
  `dns_records.managed_by` → `check_scope` raises before any write; this
  held before apps existed and is not weakened.
- Gateway ordering keeps `/.well-known/*` identity answers above all
  app-influenced serving, including redirects (§10.2.1).

### T4 — Delegation hijack
*An app writes NS/DS to hand the zone (or a subtree) to attacker
nameservers.*

- Zone-apex NS/DS: unreachable (on-chain, wallet-only; `add_record` refuses
  at `@` for everyone).
- Below-apex NS/DS: only via the explicitly dangerous `dns.delegate`
  capability — never bundled, scary consent with typed confirmation,
  refused for unverified authors (§4.2, §5.4). The registry's own rules
  still apply (≥2 nameservers, DS requires NS, etc.).
- CNAME (repoints a whole name) is treated as dangerous the same way.

### T5 — Consent phishing
*The app words its request to make a dangerous write look routine:
misleading `reason` strings, confusable URLs (`https://gооgle.com`),
record jargon that hides the effect.*

- The primary consent sentence is mediator-generated from the resolved
  plan; app strings are secondary, attributed, sanitized, length-capped
  (invariant 2, §5.4).
- URL/name rendering: punycode shown raw, confusable detection, middle
  elision only with full-value disclosure, no rich text.
- Concrete-effect wording ("make **go.2url** redirect to …"), raw records
  behind a disclosure — jargon can't be used as camouflage because it isn't
  the default rendering.
- Rate limits on consent prompts (§5.2) blunt fatigue attacks — an app
  cannot machine-gun dialogs until the user stops reading.

### T6 — Clickjacking / UI redressing of the consent surface
*The app overlays, mimics, or nests the consent UI to harvest clicks.*

- Consent is a main-owned `WebContentsView` (chrome-overlay pattern), not
  DOM: renderer content cannot read, cover, or synthesize input into it.
- Mimicry (a fake dialog drawn by the app) can at worst approve nothing —
  a fake dialog reaches no signer. The danger is teaching users to click;
  hosts should draw consent chrome outside the page viewport bounds with
  browser-trust styling for that reason.
- The provider's presence is itself gated (§5.1), so an uninstalled page
  cannot even evoke real prompts.

### T7 — Malicious or tampered manifest at install/update
*A MITM'd or hostile-server manifest, a swapped update, a manifest signed
by a stolen key.*

- Signature by the app name's control key over canonical bytes; verifying
  key anchored in the DNSSEC-signed `_hns` record (§7). Transport is not
  trusted.
- TOFU pinning of the author key per install; anchor-key changes and epoch
  bumps surface as warnings even when signatures verify (§7.4-5).
- Grants pin manifest hashes (§8): a swapped manifest cannot silently widen
  an existing grant.
- Stolen author key: bounded by the identity system's epoch rotation; hosts
  re-verify at update time. Residual: the window between theft and rotation
  — same window every code-signing system has.

### T8 — Cross-app interference on a shared name
*App A deletes or rewrites app B's records on a name both are granted.*

- Shape discrimination (§6): writes AND deletes must match the acting app's
  own declared shapes; tags are unique per installed app, collisions refuse
  install.
- Provenance ledger for audit and cleanup UI.
- Honest limit: mediator-side only; the panel's own editor is sovereign and
  the registry doesn't know apps exist. Server-side shape enforcement is
  the named v0.2 hardening (§12.1). Damage even without it is bounded to
  names the user granted to the hostile app (T2).

### T9 — Replay and request splicing
*Captured signed requests re-sent; a signature for one request applied to
another; stale mutations replayed after revocation.*

- NIP-98 binds URL (full path, config-derived base — not Host-header),
  method, and payload hash; events are single-use (`AuthEventSeen`) and
  freshness-checked, all server-side (§5.3.4). Replay dies at the registry
  even if the mediator misbehaves.
- One event per HTTP request; no pre-signing or signature caching (§5.3).

### T10 — Open-redirect abuse (2url-specific)
*Short links as a phishing/malware vector: `login-paypal.2url` → credential
harvester; redirect chains to evade filters; scheme tricks
(`javascript:`), userinfo tricks (`https://bank.com@evil.tld`).*

- Value grammar refuses non-`https`, userinfo, literal IPs, control chars
  (§10.2). `javascript:`/`data:` are unrepresentable.
- The record is written only by the *name holder* through consent — the
  authority is the same they already have over A/CNAME records; the
  shortener adds reach, not new power. Scoping the redirect to the user's
  own names is the core containment: there is no public "anyone shortens
  anything" surface in this design at all (a public 2url service would be
  a different, server-side product with its own abuse desk).
- `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`, short cache,
  self-target loop check, operator denylist (410) for reported names
  (§10.2.4). Optional leaving-Handshake interstitial (open question 3).
- `path=append` widens the surface (attacker-chosen suffix on a trusted
  short host) — flagged as possibly v1-excluded (open question 5).

### T11 — Resource abuse / rate
*Mutation floods, zone bloat, consent spam, gateway amplification.*

- Registry: zone limits (`MAX_PER_OWNER` 20, `MAX_PER_SUBTREE` 100, value
  and TTL bounds) and the locked serialized commit path.
- Mediator: per-app prompt and mutation rate limits (§5.2).
- Gateway: redirect serving is O(1), body-less, no fetch amplification;
  content path keeps its existing 25 MB cap and cache.

### T12 — Revocation gaps and orphaned records
*Revoked apps that keep acting; dead apps whose records rot or squat.*

- Revocation cuts provider access immediately; the app never held a
  credential (no tokens to leak — every action was mediated), so there is
  nothing to expire server-side.
- Cleanup is offered as an explicit consented plan; records deliberately
  outlive apps (§9) — the honest trade, stated to the user, because a
  working short link is worth more than tidiness.

### T13 — Privacy: portfolio and behavior enumeration
*An app enumerates the user's names, watches their DNS, or fingerprints
grants.*

- `names.list` returns only names granted to *this* app; the picker runs in
  mediator UI so ungranted names never transit the provider (§5.2).
- `dns.read` is filtered to the app's own shapes + pointer summary.
- Provider presence reveals only "this app is installed" to the app's own
  origin — which it necessarily knows.

### T14 — Provider/origin spoofing
*A hostile page (or subframe) impersonates the app's entry origin to
inherit its grants.*

- Injection is exact-origin, top-frame, from main (§5.1); grants key on the
  installed manifest's `ui.entry` origin. Origin integrity reduces to the
  browser's resolver/TLS story: for `*.hns.one` entries that is WebPKI +
  the L8 label promise (an entry origin must sit under the app's own name);
  for native scheme entries it is the browser's own resolution
  (DNSSEC/DANE). An app whose entry origin the author does not control
  fails review and should fail install-time lint.

### T15 — Supply chain of the app's own code
*The manifest is verified but the page's JS changes daily from the
author's server.*

- Out of scope for v0.1 beyond honesty: verification covers the manifest
  (the *authority* boundary), not the page bytes. The containment is that
  page code, however compromised, still faces T1–T14's walls — it can only
  spend the capabilities the user granted, through consent. Content-
  addressed app pages (entry = IPFS CID under the author's name, pinned at
  install) are the natural v0.2 hardening and the manifest already carries
  enough (`ui.entry` may be an `ipfs://` URL) to express it.

## 3. What the registry must keep true (unchanged, load-bearing)

The standard leans on properties the panel already enforces; regressions in
any of these are app-security regressions:

- `check_scope` + `managed_by` refuse managed/claimed/out-of-subtree writes
  for every caller (dns_records.py).
- NIP-98 URL binding uses `HNS_PUBLIC_BASE`, never the Host header;
  event ids are single-use (api_identity.py, identity.py).
- 403-vs-404 discipline: unowned names answer 404 (no portfolio oracle).
- Locked read-modify-write on the shared registry zone (REVIEW-WEB S1).
- Gateway serves `.well-known` identity endpoints above all holder content.

## 4. Residual risks, stated plainly

1. A main-process compromise is game over for local keys (pre-existing).
2. Mediator-only cross-app isolation (T8) until server-side shapes land.
3. Author-key theft window before epoch rotation (T7).
4. Unverified-app installs, if allowed, shift T2/T4/T5 onto one warning
   screen (open question 4).
5. The operator remains trusted: the registry can write any record in zones
   it serves. Receipts make identity bindings *provable*, not
   operator-proof; DNS records other than the receipted ones are operator-
   trust surface, exactly as today.
