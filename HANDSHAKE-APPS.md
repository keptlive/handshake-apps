# Handshake Apps — a proposed standard for name-driven applications

**Version 0.2 (draft) — 2026-08-22, amended 2026-09-13.**
Status: PARTLY IMPLEMENTED. Wildroot ships the mediator subset `V0.2-DELTA.md`
§M lists — install/update, grants, the provider, `version`/`names`/`identity`/
`auth.token` — against two live apps (`.pxls`, MyPastebin), plus `names.claim`
in its voucher-backed form (§5.8, 2026-09-13, MyPastebin is the reference
consumer); `records.get`, `records.propose` and `content.publish` are not built
and answer `OutOfScope`. Both apps are by the author of this document; there
are no independent implementations yet.
§11 says what exists. The manifest schema is `manifest.schema.json`
in this directory; the threat model is `SECURITY.md` and is normative — where
this document and SECURITY.md disagree, SECURITY.md wins. File and function
names in this document refer to the Wildroot browser and the HNS.ONE registry,
whose source is not public.

**Amended 2026-09-13, from two failures on a live app** (MyPastebin 1.2.0). Both
were the standard being under-specified rather than the host being careless, so
both are fixed here as well as in the host:
- §5.2 "the picker" and §5.4 — what `names.request` must actually show. A
  message box of four names is now explicitly non-conforming.
- §5.6 "which name signs" — the v0.1/D1 rule refused with `UserDeclined` when
  several names were granted and none was the primary. Refusing on a host-side
  ambiguity is not the user declining; there is now a third rung.
- §5.7 — the error table, which did not exist, plus the requirement that `code`
  is a property of the rejected `Error`.
- §8 "Update / when the host looks" — the update flow had no trigger, so a
  conforming host could satisfy every word of it and never once re-read a
  manifest. That is what happened.
- §5.8 `names.claim` — the op v0.1 sketched as "claim a free label under a
  declared TLD" assumed an OPEN TLD. A partner TLD (`.mypastebin`) is claimed
  only with a token that must never enter a browser, so the reference app
  minted the user's key on its server and handed a key file over. The voucher
  model replaces that: the app's server vouches, the browser claims. One key
  per name, in the vault, like every other name.

---

## 0. The problem, in one paragraph

It is hard to *use and assign Handshake names inside an application*. The
pieces exist — a user holds names, a browser (Wildroot / HNS.ONE) holds each
name's control key in its vault, and a registry panel accepts NIP-98-signed
DNS mutations — but every app that wants to say "point `foo.2url` at this
URL" has had to be built by us, by hand, inside the browser. This standard
defines the shape that lets **anyone** build such an app: the app declares
*what* it wants written, in a manifest; the **browser** shows the user the
concrete effect, obtains consent, and signs with the control key; the app
never sees a key, a signature, or the signing surface. Two worked examples
prove the shape: `pinthis` (the IPFS publishing flow that already exists,
expressed retroactively) and `2url` (a new link shortener), in `examples/`.

## 1. Roles and vocabulary

| Term | Meaning |
|---|---|
| **App** | Untrusted third-party code + a signed manifest. Runs as an ordinary web page (or packaged page); has **no** privileged access. |
| **Mediator** | The browser's privileged main process. Holds the vault, renders consent, signs NIP-98, talks to the registry. The only trusted computing base on the client. |
| **Registry panel** | The HNS.ONE web app. Enforces ownership (`resolve_target`), record validity (`dns_records.py`), managed-record locks, and limits. Already exists. |
| **Gateway** | `gateway.py` — serves a name's published content and identity endpoints from its zone records. |
| **Name** | A Handshake name the *user* holds: either a free label under an open registry TLD (owned by a control key, no account) or an imported TLD/SLD (owned by an account, drivable by a linked control key). |
| **Control key** | The name's BIP-340 key, generated and stored in the browser vault (`browser/src/identity/identity-account.js`). Signs claim receipts and NIP-98 requests **in the main process only**. |
| **App name** | The Handshake name that *identifies the app itself* (`2url`, `pinthis`). App identity is a Handshake name — see §7. |

Trust stance, stated once and assumed everywhere: **the app author is
hostile, the user is naive, the mediator and registry are trusted.** Every
rule below exists to make that combination safe.

## 2. The five invariants

These are not features; they are the definition of a conforming
implementation. An implementation that violates any of them is not a
Handshake-Apps host, whatever else it does.

1. **Keys never cross.** No app-reachable surface returns private key
   material, produces signatures over app-chosen bytes, or exposes a generic
   signing oracle. The mediator signs only the specific, schema-valid
   requests this standard defines, after consent. (An app that could obtain a
   NIP-98 signature over an arbitrary URL+body owns every panel endpoint —
   that is the attack, and the reason there is no `sign()` verb.)
2. **The user consents to effects, not requests.** Consent UI renders what
   will actually be written — owner, type, value, and a plain-language
   sentence — generated by the *mediator* from the resolved plan, never from
   app-supplied text. App strings may appear only as visibly-attributed,
   sanitized secondary text.
3. **Least privilege, statically declared.** An app can only do what its
   manifest declares, on names the user has granted it, and the declaration
   is narrow: record shapes (owner pattern + type + value pattern), not
   record types alone.
4. **The registry's rules still apply.** Everything the mediator sends goes
   through `POST /api/dns/mutate` / `/api/dns/pointer` / `/api/identity/claim`
   with all of `dns_records.py`'s scope checks, validators, managed-record
   locks and limits intact. The app system adds restriction on top; it never
   bypasses or reimplements the server's rules.
5. **Locked surfaces are unreachable, not merely undeclared.** `_hns.*`,
   `_atproto.*`, OPENPGPKEY, SMIMEA, DANE-managed TLSA, and the zone-apex
   NS/DS are refused by the mediator *and* the registry regardless of what a
   manifest asks for. There is no capability string that grants them.

## 3. The manifest

A single JSON document, canonical name `<app>.app.json`, media type
`application/hnsapp+json`. Machine-validated against
`manifest.schema.json` (JSON Schema 2020-12). Top-level shape:

```json
{
  "manifest_version": 1,
  "id": "2url",
  "app": {
    "name": "2url — link shortener",
    "version": "0.1.0",
    "author": { "name": "…", "handshake": "2url", "contact": "…" },
    "homepage": "https://2url.hns.one/",
    "description": "Short links on names you own."
  },
  "tlds": ["2url"],
  "capabilities": [ … ],
  "records": { … },
  "ui": { "entry": "https://app.2url.hns.one/" },
  "gateway": { "requires": ["one.hns.gateway.redirect.v1"] },
  "signature": { … }
}
```

Field semantics:

- **`manifest_version`** (int, required). This document defines version `1`.
  A host that does not recognize the version MUST refuse to install. Within a
  version, **unknown fields MUST be ignored** (forward compatibility), but a
  host MUST NOT ignore unknown *capability* entries — an ungranted capability
  is safe, an unrendered one is not, so unknown capabilities make the install
  fail closed (§4).
- **`id`** (string, required). The app's identity: a Handshake name the
  author holds, lowercase, matching the registry's `LABEL_RE`-per-label
  grammar. Two manifests with the same `id` are versions of one app; grants
  are keyed by `id`. Because the id is a Handshake name, authorship is
  provable (§7) and no central namespace authority exists.
- **`app`** (object, required). Display identity. `app.author.handshake`
  MUST equal `id` when present. `app.version` is semver; hosts use it only
  for display and update ordering — *capability diffs*, not version numbers,
  drive re-consent (§8).
- **`tlds`** (array of strings, required, may be empty). The zones the app
  operates in. A capability whose scope is `"claimed-label"` is only
  satisfiable by names under these TLDs. An app may instead declare scope
  `"any-held-name"` per-capability to operate on whatever names the user
  explicitly grants (pinthis's shape — publishing is not TLD-specific).
  `tlds` is a *ceiling*, never a grant: holding the manifest conveys nothing.
- **`capabilities`** (array, required). §4.
- **`records`** (object, required if any DNS capability is declared). The
  exact record formats the app's function depends on — its public,
  documented data contract. Keyed by a record-schema id, each entry gives
  `owner`, `type`, `value` (a template with a literal prefix), `limit`
  (max records of this shape per name), and prose `meaning`. Consent UIs and
  revocation both use these shapes to find "this app's records" (§6, §9).
- **`ui.entry`** (string URL, required). The page the host opens as the app,
  and the **only origin** that receives the provider (§5). It MUST be an
  origin the app's author controls under their own name — for our stack
  that means `https://<label>.<id>.hns.one/`, `https://<id>.hns.one/`, or a
  native scheme URL for first-party apps. An app never gets an `hns.one`
  label that is not its own name.
- **`gateway.requires`** (array of strings). Serving behaviors the app
  depends on, as namespaced feature ids (§10 defines
  `one.hns.gateway.redirect.v1`). A host SHOULD warn at install when the
  user's gateway does not advertise a required feature; the app must degrade
  honestly.
- **`signature`** (object, required for distribution; §7). Detached BIP-340
  signature by the app name's control key over the canonicalized manifest
  with `signature` removed.

Canonicalization for hashing/signing: JSON with keys sorted, no
insignificant whitespace, UTF-8 (RFC 8785 JCS). The **manifest hash**
`sha256(canonical_bytes)` identifies an exact manifest everywhere below.

## 4. Capabilities

A capability is one entry in `capabilities`, shaped:

```json
{
  "cap": "dns.set-record",
  "scope": "claimed-label",
  "record_schema": "redirect",
  "reason": "Point your short link at its destination."
}
```

`cap` is a namespaced verb from the registry below. `scope` is where it
applies. `record_schema` names an entry in `records` — for DNS verbs it is
**required**: there is deliberately no way to request "TXT records" in
general, only "TXT records of exactly this shape". `reason` is app-supplied
prose the consent UI may show as attributed secondary text (never as the
primary sentence — invariant 2).

### 4.1 Capability registry (v0.1)

| `cap` | Effect | Maps to |
|---|---|---|
| `names.claim` | Register a NEW name under one of the app's declared `tlds` for the user, keyed by a fresh control key in the user's vault, on a **voucher** the app's server obtained from the registry (§5.8). Supersedes v0.1's `name.claim`, which is not honored by any host — it assumed an open TLD, and the one app that needs this runs on a partner TLD. | Browser `claimIdentity` (+`voucher`) → `POST /api/identity/claim`; the app's server → `POST /api/identity/partner/voucher` |
| `name.list` | See which of the user's names *this app has been granted* (never the full portfolio). | Mediator grant store; `/api/identity/names` for state |
| `dns.read` | Read the records matching the app's declared `records` shapes, plus pointer state, on granted names. | `GET /api/dns/records`, filtered by the mediator |
| `dns.set-record` | Add or update records matching one declared shape on a granted name. | `POST /api/dns/mutate` (`add`/`update`) |
| `dns.remove-record` | Delete records matching one declared shape on a granted name. | `POST /api/dns/mutate` (`delete`) |
| `content.publish` | Submit content for pinning + pointer write through the publish pipeline (the pipeline writes `ipfs=<cid>` TXT + gateway A itself). | `POST /api/publish` |
| `identity.authenticate` | Mint a NIP-98 token proving the user controls a granted name, bound to one request at the **app's own origin** — authenticates the user to the *app's server*, never the registry (§5.6). Ships today as the extension `one.hns.auth.nip98`. | Mediator `appAuthToken` → `signAuth`; verified by the app's own server |
| `dns.delegate` | **Dangerous.** Write NS (and DS) at a granted name — hands the subtree to external nameservers. | `POST /api/dns/pointer` mode `ns` |

The read-only `identity` capability (reading the user's MAIN identity as public
info) is not in this table because it writes nothing and touches no name — it
is declared in the separate `permissions` map, see §5.5.

Scopes: `claimed-label` (names under `tlds` that the user claimed/granted
through this app) and `any-held-name` (any name the user explicitly grants —
still one name at a time, still consent-gated; the scope changes what the
picker offers, not the consent requirement).

Extensibility: capability ids are namespaced strings. Ids without a dot-
namespace prefix (`dns.*`, `name.*`, `content.*`) are reserved for this
standard. Third parties may define `com.example.custom-cap`; a host that
does not implement a declared capability MUST fail the install with the
capability named (fail closed — see §3 `manifest_version`).

### 4.2 What no capability can grant

The mediator refuses these before the network is touched, and the registry
refuses them again server-side (`dns_records.managed_by`, `check_scope`,
`add_record`); both refusals are required — the second is what makes a
compromised mediator not a registry compromise:

- Any owner under `_hns` or `_atproto` — the identity anchors. Writing them
  is name/handle hijack (dns_records.py `MANAGED_PREFIXES`).
- OPENPGPKEY / SMIMEA anywhere — mail-encryption flow's (`MANAGED_TYPES`).
- TLSA at `_443._tcp` on DANE-enabled zones — certificate pinning's.
- NS/DS at a zone apex — on-chain, wallet territory (`add_record`'s refusal).
- Records on names the user has not granted to the app, records on other
  users' names, records outside the app's declared shapes — including other
  apps' records at the same owner (§6).
- Types outside `dns_records.USER_TYPES`.

`dns.delegate` (NS/DS below the apex) and any shape containing CNAME are
**dangerous capabilities**: hosts MUST render them with an explicit warning
("hands this name's subtree to servers outside your control" /
"repoints the whole name"), MUST NOT bundle them into an "accept all"
affordance, and SHOULD refuse them entirely for apps with unverified
authorship (§7).

## 5. The mediation contract — `window.handshake`

### 5.1 Injection

The provider is injected **only** into frames whose origin exactly matches
the installed manifest's `ui.entry` origin, from the main process, with
`contextIsolation` on. No provider for
uninstalled apps, iframes of other origins, or `file:`. Presence of the
provider is therefore itself a statement: "this page is an installed app".

**The provider arrives LATE, and apps MUST NOT read its absence as an answer.**
A host that decides "is this origin an installed app?" in its main process
cannot inject the provider until that question has been answered, so on a cold
start — or a tab restored while the browser is still starting its own
subsystems — `window.handshake` is **undefined when the page's script runs**.
An app that tests `typeof window.handshake` once, at load, and concludes "not
this browser" will hide its own feature and, if it binds its controls after
that test, leave a button that does nothing for the life of the page. That
happened to the reference app on 2026-09-13.

So an app MUST treat a missing provider as *not yet*, poll for it to the same
deadline it gives any other presence probe (the reference app: 12 s), and bind
every control **before** it awaits anything. Hosts SHOULD additionally fire a
`handshake#initialized` event on `window` when the provider lands, so an app
need not poll; an app MUST still work if the host does not.

### 5.2 Surface (v0.1)

All methods return Promises of JSON-serializable plain data. Nothing here
ever returns key material, signatures, receipts' signing inputs, or the
user's full name list. Every mutating verb may raise `UserDeclined`,
`NotGranted`, `OutOfScope`, `RateLimited`, `RegistryRefused {message}`,
`NeedsConfirm {reason}` — machine-readable `code` plus prose.

```ts
interface HandshakeProvider {
  // Identity of the provider + the app's own granted view.
  version(): Promise<{ standard: "0.1", host: string, capabilities: string[] }>

  names: {
    // Names ALREADY granted to this app, with per-name state.
    list(): Promise<Array<{ name: string, tld: string, granted: string[] }>>
    // Ask the user to grant an existing held name (picker is mediator UI;
    // the app never sees names the user did not pick). See "the picker".
    request(opts: { tld?: string }): Promise<{ name: string }>
    // Register a NEW name under one of the manifest's `tlds` for the user, on
    // a voucher the app's OWN server obtained (§5.8). Mediator: manifest gate
    // -> consent -> key generation in vault -> receipt signed in main ->
    // /api/identity/claim with `voucher` -> grant recorded.
    claim(opts: { tld: string, label: string, voucher: string })
      : Promise<{ name: string, expires_at: string | null }>
  }

  records: {
    // Only the app's declared shapes (+ pointer summary), on a granted name.
    get(opts: { name: string }): Promise<{
      records: Array<{ owner: string, type: string, value: string, ttl?: number }>,
      pointer: object, limits: object
    }>
    // THE one mutation verb. `changes` reference declared record_schemas;
    // the mediator resolves them to a concrete plan, shows consent, signs,
    // POSTs /api/dns/mutate (one call per change, or /api/dns/pointer for
    // pointer-shaped plans), and reports what happened.
    propose(opts: {
      name: string,
      changes: Array<
        | { op: "set",    schema: string, fields: Record<string, string> }
        | { op: "remove", schema: string, match?: Record<string, string> }
      >
    }): Promise<{
      applied: Array<{ owner: string, type: string, value: string }>,
      removed: Array<{ owner: string, type: string, value: string }>,
      sign_state: "signed" | "unsigned" | "queued"
    }>
  }

  content: {  // only with content.publish
    publish(opts: { name: string, files: Array<{ path: string, bytes: Blob }> })
      : Promise<{ cid: string, gateway_url: string, state: string }>
  }
}
```

Notes that are part of the contract, not commentary:

- **`propose` takes schema references, not raw records.** The app says
  `{ op: "set", schema: "redirect", fields: { url: "https://…" } }`; the
  *mediator* expands the manifest's `records.redirect` template into the
  concrete `{ owner, type, value }`, validates the fields against the
  template's field grammar, and refuses anything that does not expand
  cleanly. Raw record dicts from the app are never forwarded. This is what
  makes "the consent screen shows exactly what will be written" enforceable
  rather than aspirational.
- **One consent, one plan.** A `propose` with several changes is one consent
  dialog rendering the whole plan (the `plan_pointer` preview philosophy:
  the same resolved plan is what gets committed, so preview and effect
  cannot disagree). Partial application is not allowed; the mediator applies
  changes in order and stops (reporting position) on the first registry
  refusal.
- **`NeedsConfirm` passes through.** When the registry answers 409
  (`needs_confirm: true` — e.g. the change would remove a published site's
  pointer), the mediator re-renders consent with the registry's reason and,
  only if the user confirms, retries with `confirm: true`. Apps never get to
  set `confirm` themselves.
- **The picker** (`names.request`, normative; written into v0.2 after the
  reference host shipped the wrong thing). It is mediator chrome the app cannot
  reach, and it **MUST**:
  - offer **every** name in scope — the whole held list when `tld` is omitted
    (D4), the matching ones when it is present. **No cap.** A picker that shows
    the first few names makes the rest unreachable with no way for the user to
    know;
  - answer with the **name chosen**, never with a positional index the host
    maps back. The mediator **MUST** re-check the answer against the list it
    actually offered and treat anything else as a cancel;
  - present a stable order the user can predict: the primary name first
    (§5.5), then the rest in the host's own stored order — never re-sorted, so
    the same names do not read as a different set here than elsewhere;
  - show, per name, whether this app **already holds** it, so the choice means
    something;
  - be keyboard-operable, with one explicit *choose* and one explicit *cancel*;
    a closed picker is a cancel;
  - **always be shown.** If the host cannot parent the picker to a window, it
    shows it unparented. Returning "the user declined" because the host could
    not find a window is the host lying about the user (§5.7 `UserDeclined`);
  - leave one log line per invocation naming the app, how many names were
    offered and what was chosen or that it was cancelled. A picker that failed
    silently is the one failure a bug report cannot describe.

  Rejected explicitly: a native message box with the names as buttons. It caps
  the list, answers with a platform-assigned index, cannot show which names the
  app holds, and — with no parent window — can return a cancel the user never
  pressed. The reference host shipped exactly that and a user who picked their
  name was told `UserDeclined: no name chosen` (2026-09-13).
- **Rate limits.** Per app id, mediator-enforced, before consent UI is even
  shown: default 6 consent prompts/minute and 60 accepted mutations/day
  (defaults, host-configurable). This bounds consent-fatigue attacks; the
  registry's zone limits (`MAX_PER_OWNER` 20, `MAX_PER_SUBTREE` 100) bound
  the damage of an accepted grant.

### 5.3 The signing path (normative)

For a granted, in-scope, consented plan the mediator, in the main process:

1. Loads the name's control key from the vault
   (`storedIdentity` → `controlKeyFromSecret`) — the `bindAtproto` pattern:
   key in scope only inside the privileged function, never across IPC.
2. Builds the exact JSON body for `POST /api/dns/mutate` (or
   `/api/dns/pointer`, `/api/identity/claim`, `/api/publish`).
3. Signs a NIP-98 (kind-27235) event over `{url, method, body}` with the
   control key (`signAuth`), producing only the `Authorization` header.
4. POSTs via `panelPost`. The registry re-verifies signature, URL binding
   (`HNS_PUBLIC_BASE`, full path), payload hash, freshness, and single-use
   event id (`AuthEventSeen`) — replay is dead server-side, not by mediator
   politeness.
5. Returns to the app only: applied/removed records, `sign_state`, errors.

The mediator MUST NOT cache signatures, pre-sign, or batch-sign beyond the
consented plan. Each NIP-98 event covers exactly one HTTP request.

### 5.4 Consent UI requirements

- Rendered by the mediator as **main-process-owned chrome** (the share-panel
  / `WebContentsView` overlay pattern — never DOM inside or over the app's
  renderer), so the app cannot draw over, read, or click it. Non-mediator
  content MUST NOT be able to overlay it (clickjacking).
- Primary content: one sentence per change, concrete effect first —
  *"2url will make **go.2url** redirect to `https://example.com/deep/link`"* —
  with the raw record (`go  TXT  "redirect=…"`) available behind a
  "show record" disclosure, not as the default rendering.
- Shows the app id, its **authorship verification state** (§7) with
  unverified rendered as a warning, and the name being written to.
- Target URLs and names are rendered with confusable/IDN-safe display
  (punycode shown raw, no app-controlled rich text, values elided in the
  middle beyond a length cap with full value on disclosure).
- Dangerous capabilities per §4.2 get a distinct, scarier treatment and a
  typed confirmation for `dns.delegate`.
- Every grant screen offers "just this once" and "remember for this app on
  this name"; remembered grants are listed and revocable in browser settings
  (§9). A remembered grant still shows a non-blocking notice per mutation
  batch ("2url updated go.2url ✓") — silent writes are never allowed,
  auditability is part of consent.

### 5.5 The `identity` capability — reading the user's MAIN identity

An app that wants to frame the experience around *this* user — "your short
links", "signed in as **matt.w3**" — declares a **read-only permission**,
separate from the DNS `capabilities` array because it writes nothing and
touches no name's records:

```json
"permissions": { "identity": "read" }
```

The provider surface:

```ts
identity(): Promise<{
  name: string,     // the native display form, e.g. "matt.w3"
  native: string,   // === name, so an app never has to know the display rule
  label: string,    // the first label, "matt"
  npub: string | null,   // the public nostr id
  nip05: string | null,  // "_@matt.w3.hns.one", present once the name is claimed
  claimed: boolean
} | null>            // null when the user has no identity yet
```

Normative rules:

- **Public information only.** The op returns the four public facts about the
  user's chosen MAIN name and nothing else. It NEVER returns a secret key, an
  nsec, a receipt, the control key, or the user's *other* names (invariant 1;
  the portfolio-privacy asset, SECURITY.md T13). The value is built expressly
  to cross the app boundary.
- **The MAIN name, one answer everywhere.** It is derived from the browser's
  single `primaryIdentity` — the name the user marked as main, else their
  earliest claim — so Mail, Social and every app answer "whose browser is
  this?" with the same name and cannot drift.
- **Opt-in and visible.** The op is refused unless the manifest declares
  `permissions.identity: "read"` (the manifest gate, on top of the two
  transport gates). A first-party app is held to the same declaration as any
  third party, on purpose. A manifest that cannot be read grants nothing
  (fail closed).
- **Maps to `names.primary`.** A host may also surface this as
  `names.primary(): { name, tld } | null` (V0.2-DELTA D2). Both read the same
  `primaryIdentity`; an app must never guess `list()[0]`, which signs people
  in as the wrong identity.

Reference implementation: `browser/src/identity/app-identity.js`
(`appMainIdentity`), gated by `browser/src/protocols/app-manifest.js`
(`manifestGrantsIdentity`); the `2url` app is the reference consumer and shows
"Signed in as **matt.w3**" from it.

### 5.6 `identity.authenticate` — proving a name to the app's OWN server

Every capability in §4 mediates *app → registry*. An app with server-side
state (a leaderboard, a canvas, a saved document) needs one more thing first:
to authenticate a user to **its own server**. `names.list()` reporting
`matt.w3` is not proof of anything — it arrives over the wire from the party
it flatters (§5.2, and see the normative note below). `identity.authenticate`
is the verb that turns "the client says it is matt.w3" into "matt.w3's own
control key signed this request".

Declared as a capability (not a `permission`, because it acts under a granted
name):

```json
{ "cap": "identity.authenticate", "scope": "any-held-name",
  "reason": "Prove which name is placing a pixel." }
```

The provider surface:

```ts
auth: {
  // A NIP-98 (kind 27235) Authorization header, signed by the control key of a
  // granted name, bound to ONE request at the APP'S OWN origin.
  token(opts: {
    url: string,      // absolute; MUST be same-origin with a ui.entry origin
    method: string,   // uppercased by the mediator
    body?: string,    // the exact bytes to be sent, or omitted
    name?: string     // which granted name; see "which name signs" below
  }): Promise<string> // "Nostr <base64 event>"
}
```

**Which name signs** (normative; corrected in v0.2 — see the note). An app
SHOULD pass `name`: it already knows who it is signing in, and its server
verifies the signature against *that* name's `_hns` record, so a token minted
under any other name fails at the server rather than in the mediator. When
`name` is absent the mediator resolves it in this order, and MUST NOT refuse
while a rung remains:

1. the sole granted name;
2. the user's primary name, if it is granted to this app;
3. **the name most recently granted to this app.**

Only an app with **no** grant at all is refused, and the code is `NotGranted`
(with "ask for one with `names.request()`"), never `UserDeclined`.

> **Why rung 3 exists.** The first draft of this verb (V0.2-DELTA D1) said
> "default = the single grant, else `UserDeclined` if ambiguous". That is
> wrong, and shipping it proved it: a user who had granted an app two names,
> neither of them their main identity, pressed *Sign in* and the app was told
> **the user declined** — a false statement about someone who had said yes
> twice. Ambiguity in the host is not a refusal by the person. The freshest
> name they chose *for this app* is not a guess; it is the last answer they
> gave, and hosts MUST record grant order so they can give it.

**The app's own server MUST answer the browser's CORS preflight for every
`ui.entry` origin** (normative, and learned the hard way twice). A native app
on a Handshake name runs at `hns://<name>` while its API is at
`https://<name>.<gateway>` — **different origins by construction**, so every
call the app makes is cross-origin and the browser sends `OPTIONS` first. A
server that assumes same-origin answers 405 and the sign-in dies before it is
sent. The allow-list is the manifest's `ui.entry` origins and nothing else:
echo the request's `Origin` when it is one of them, never a wildcard (these
routes carry a bearer and act on its holder's behalf), and send `Vary: Origin`.

Echo it on the **successes too**, not only on the refusals. A 200 without
`Access-Control-Allow-Origin` is a session the server minted and the browser
threw away: the user sees "could not be reached" while the row sits in the
table. The reference service shipped exactly that bug on 2026-09-13 because
`req` was an optional last argument that every error path passed and the two
success paths did not — and every wire-level smoke it had only ever exercised
401/404/405. Test a *successful* signed-in request with an `Origin` header, or
the header matrix you believe you have is untested where it matters.

Mediator obligations (normative):

1. **The origin check is the whole security property.** REFUSE any `url` whose
   origin is not one of the installed manifest's `ui.entry` origins. This is
   what stops the verb being a signing oracle: without it an app could mint a
   NIP-98 header aimed at `/api/dns/mutate` and own every registry endpoint
   (invariant 1, SECURITY.md T1). A token for `https://hns.one/api/dns/mutate`
   is refused *in the mediator*.
2. Sign only with the **control key** of a name **granted to this app** — the
   key whose public half the name's `_hns` record anchors, which is exactly
   what the app's server verifies against.
3. `created_at` is the mediator's clock; the event is single-use. Never cache,
   pre-sign, or reuse one (§5.3).
4. Return only the header string. Never the key, never the raw event.
5. Rate-limit per app id, as for mutations.

**Consent: granted once at install, NOT prompted per call.** It authenticates
to the origin the user is already looking at and writes nothing, anywhere. A
prompt per call would put a dialog in the hot path of a game and teach users
to click through consent — the failure §5.4 exists to prevent. The install
line says what it is: *"pxls will be able to prove you are **matt.w3** to
pxls.hns.one. It cannot use this to change your names or records."*

**Sign-in is AUTOMATIC once granted; a picker is for the first time or for
switching.** (Recommended app behaviour, and the reference apps' behaviour.)

A grant is durable: it lives in the host's own app store, survives restarts,
and *is* the statement "this app may act as this name". An app that opens its
name picker on every load is asking the user to re-answer a question they have
already answered — and training them to click through consent, which is the
failure §5.4 exists to prevent. So on load an app SHOULD:

1. call `names.primary()`; if it answers a name, that name is granted (D2
   guarantees `null` unless it is), else
2. call `names.list()`, which returns **only** granted names (invariant 1), and
   take the first, else
3. show nothing but a sign-in control — nothing is granted yet, and *that* is
   what the picker is for;

and when 1 or 2 gave a name, call `auth.token({..., name})` and complete its own
sign-in with **no picker and no click**. The picker reappears only for a "switch
name" control the user presses deliberately.

What is NOT automatic is the app's own **session**. The reference app keeps its
bearer in page memory and lets it die with the tab: a grant and a session are
different risks, and "I do not have to sign in again" is a statement about the
grant. Apps SHOULD say plainly who they signed in as, and offer *switch* and
*sign out* beside it.

Apps SHOULD pass `{name}` to `auth.token` once they know which name they mean
(§5.6 ladder rung 1): the app already knows, and the server verifies the
signature against that name's own `_hns` record, so a token signed as anyone
else fails there rather than in the host.

**A provider's name list is not an authentication result** (normative, and the
reason this verb exists). An app's *server* MUST independently verify any
identity it acts on — for a Handshake name, against that name's own `_hns`
control record, or by verifying an `identity.authenticate` token. Apps MUST
NOT treat `names.list()` / `names.request()` output as proof of control.

Reference implementation: `browser/src/identity/app-attest.js`
(`appAuthToken` — the manifest gate, the origin gate, and the control-key
NIP-98 signing) over the existing `signAuth`. `.pxls` is the reference
consumer: its client calls `auth.token(...)` and its server
(`pxls/server/pxls/auth.py`, `names.py`) verifies the NIP-98 header and then
resolves the name's `_hns` control record — the shipped signer meeting the
shipped verifier is covered end to end by
`pxls/tests/test_api.py::test_browser_minted_token_opens_a_verified_session`.
`.pxls` ships today against the extension id `one.hns.auth.nip98`; hosts and
`manifestGrantsAuth` accept it or the standard `identity.authenticate`
interchangeably, so the app promotes to the standard id without a flag day.

### 5.7 The error contract (normative)

§5.2 said errors carry "machine-readable `code` plus prose" and never said
what the codes are, so every host was free to invent them and no app could
switch on one. The table is now part of the standard.

**The shape an app sees.** Every operation returns a Promise. A refusal
**MUST** reject with an `Error` whose

- **`code`** property is one of the ids below — this is what an app branches
  on, and it **MUST** be present as a property, not only inside the text; and
- **`message`** is `"<Code>: <prose>"` — the code repeated in the text, because
  custom `Error` properties do not reliably survive every host's page boundary,
  and an app that lands in a generic `catch` must still be able to say
  something true. The prose is the host's; it is a sentence for a person, and
  apps **MUST NOT** parse it.

Internally the operation should resolve an envelope (`{ok:false, code,
message}`) across the process boundary and let the injected shim build the
`Error`, so codes stay stable rather than depending on how the engine mangles
a thrown value across a bridge.

| `code` | Means | Typical cause |
|---|---|---|
| `NotGranted` | The app may not do this. | Not an installed app frame; the capability is not in its manifest; the name it asked to sign as is not granted; it has no grant at all yet. |
| `UserDeclined` | The user was asked and said no. | The name picker was cancelled or closed; there was nothing to choose (the user holds no name in scope). **Never** used for a host-side ambiguity or a locked key store. |
| `OutOfScope` | This host will not do it at all. | An operation this host does not implement; a `url` outside the app's own entry origins; an unknown verb. |
| `RateLimited` | Too many requests from this app id. | The per-app token bucket, checked before signing and before any consent UI. |
| `VaultLocked` | The key store could not be read. | A password-protected vault. **Not a refusal** — the message says how to unlock it (§5.3, §5.6). |
| `Unavailable` | Something the host depends on failed. | The names could not be read; a backing service could not be reached. |

A host MAY define further codes **for one capability's own outcomes** (the
reference host does, for `content.publish.paste`, and §5.8 does for
`names.claim`: `VoucherRejected`, `Cap`, `Taken`, `InvalidRequest`), and when
it does it MUST publish them with that capability. It MUST NOT redefine any id above, and it
MUST NOT emit a code it has not published: an undocumented code is a code
nobody can handle. The reference host pins this mechanically — its test reads
the surface source back and fails on any code missing from the published
table.

An app that receives a code it does not know MUST treat it as a plain failure
and show the host's `message`; it MUST NOT show a raw `"<Code>: <prose>"`
string to a person, which is the app's own bug, not the host's.

**A host MUST log every refused operation with its code** (normative).

    [handshake-apps] op=<op> app=<id> code=<Code> ms=<elapsed> — <message>

and MUST log a line when it mints an `identity.authenticate` token:

    [handshake-apps] op=auth.token app=<id> name=<name> method=<M> url=<host+path> minted

A refusal that is clean on the wire and silent in the log is a refusal nobody
can diagnose. On 2026-09-13 a user pressed *Sign in*, the app showed a banner
he did not relay, and the host's log — which recorded the name picker's own
line perfectly — said nothing whatever about what happened next. The whole day
that followed was spent guessing between six codes any one of which would have
been one line of log. A host MUST NOT make a person the transport for its own
diagnostics.

The line **MUST NOT** contain the token, the raw event, any key, the request
body, or any request header; a url is reduced to its **host and path** (a query
string can carry anything and this line lands in a file).

**A host SHOULD also announce an operation that has not settled.** An operation
that never resolves produces no outcome to log, by definition, and from the
page it is indistinguishable from a dead button — the exact shape of *"I click
it and nothing happens"*. The reference host logs on a ladder (5 s, 15 s, 45 s):

    [handshake-apps] op=<op> app=<id> STILL RUNNING after <n>ms — it has not answered the page

### 5.8 `names.claim` — a new name for the user, issued through an app

**The problem this solves, stated once.** An app on a Handshake TLD it holds
(MyPastebin on `.mypastebin`) wants its user to have `<label>.mypastebin`.
Two authorities have to meet for that, and they live in different places:

- the **registry's permission** to issue under that TLD — under the partner
  surface that is a **partner token**, a credential that speaks for every name
  under the TLD and therefore must never enter a browser (§1, SECURITY.md T1);
- the **name's own key** — which `POST /api/identity/claim` requires as the
  request's signer (`pubkey == signer`), and which must live in the user's
  vault and never reach a server (invariant 1).

Until 2026-09-13 the reference app resolved this by minting the key on its
server, claiming with it, and handing the user a key file to import — a name
the user did not hold until they did a second thing, and a server that had
held a control key it then had to promise it had forgotten. That is not the
ownership model of any other name, and it is not this standard's.

**The voucher model.** The app's server asks the registry for a **voucher**:
a one-shot, minutes-long permission for exactly one label under its TLD, bound
to the sponsoring identity (the user's signed-in name) and carrying the
pointer records the new name should serve (the app's own content). The server
hands the opaque voucher string to its page; the page hands it to the host.
The host then runs **the same claim it runs for every name** — key generated
in the vault, receipt signed in the privileged process, NIP-98 by the new key
— presenting the voucher in place of a partner token. The registry honors the
voucher for that label only, counts the allowance against the sponsor the
partner named (never one the redeemer chose), writes the pointer in the same
request, and consumes the voucher in the same transaction as the claim.

The result is a name like any other in the vault: **one key per name**, held
only by the user, exportable, delegable, and usable by every op the app holds
the moment the call returns. No key file, nothing to import, no token in a
browser, no key on a server.

**The manifest.** The app declares the capability and the namespace:

```json
"tlds": ["mypastebin"],
"capabilities": [{ "cap": "names.claim", "scope": "claimed-label",
                   "reason": "Register a .mypastebin address of your own." }]
```

A host honors `names.claim` only for a `tld` listed in the manifest's `tlds`
(§3: `tlds` is the ceiling). An app that opts in but declares no `tlds` has
asked for nothing; the host lists nothing under `version().capabilities`.

**The op.**

```ts
names.claim(opts: { tld: string, label: string, voucher: string })
  : Promise<{ name: string, expires_at: string | null }>
```

`expires_at` is the registry's own date for the claim (ISO 8601), or `null`
for a name that does not lapse. A host MAY add `already_held: true` when the
name was already claimed in this vault and was merely granted.

**Host obligations** (normative, in order):

1. Refuse `NotGranted` unless the installed manifest declares `names.claim`
   AND lists `tld` in `tlds`.
2. Check the shape of `label` (LDH, 1–63) and `voucher` (non-empty, bounded)
   before anything else; refuse `InvalidRequest`. The registry, not the host,
   decides length floors and reservations, and says so in words.
3. Rate-limit per app id before any consent UI (§5.2): a claim is both a
   prompt and a registry write.
4. Read the vault; a locked key store is `VaultLocked`, never a refusal
   (§5.7). A vault that does not exist yet MAY be created here — a name needs
   somewhere to live, and the welcome page does the same.
5. **Consent, in the host's words**, naming the app and the exact name:
   *"MyPastebin wants to register **alpha.mypastebin** as a new name in your
   vault."* — with the detail that the key is created in the host and the app
   never sees it, that the app may act as the name as it acts as any granted
   name, and that names under this TLD may lapse. App-supplied text appears
   only as attributed secondary text (invariant 2). "Not now" is
   `UserDeclined`, and nothing has been generated or sent at that point.
6. Run the host's ordinary claim (§5.3 signing path) with `voucher` in the
   body. The body carries **no sponsor** and the request **no partner token**
   — the host has neither, by design. The registry's refusal codes map onto
   this capability's codes (below); the registry's own sentence for the cap
   and a taken name is what a person should read, so the host relays it.
7. On success: store the identity row with the registry's `expires_at` and
   the issuing app's id (`issuedBy`), **grant the name to the app at once**
   (the user just consented to exactly that), log one line naming the app,
   the name and the date — never a key — and return `{name, expires_at}`.
8. On a definitive registry refusal (a code), discard the unclaimed key the
   claim wrote before asking; on an unreachable registry keep it, because the
   claim may have landed with the answer lost, and the host's ordinary
   half-claim healing applies.

**Codes** (this capability's own, per §5.7):

| `code` | Means |
|---|---|
| `VoucherRejected` | The registry would not honor the voucher: used, expired, not one it issued, or issued for another name or TLD. Ask the app for a new one. |
| `Cap` | The sponsor already holds the allowance under this TLD. The message is the registry's sentence. |
| `Taken` | Somebody else claimed the label between the voucher and the claim. The message is the registry's sentence. |
| `InvalidRequest` | The label or voucher has no acceptable shape (host), or the registry refused the label itself (reserved, too short). |

plus `NotGranted`, `UserDeclined`, `RateLimited`, `VaultLocked`,
`Unavailable` with their standard meanings.

**Registry obligations** (normative for a registry that supports this flow):

- `POST /api/identity/partner/voucher`, gated exactly as a partner claim is
  (the TLD's partner token, server-to-server, no CORS): body
  `{tld, label, sponsor_pubkey, ttl_seconds?, pointer?: {cid, ip?}}` →
  `201 {voucher, tld, label, name, sponsor, expires_at, claim_ttl_days,
  limit, held}`. It checks availability, the label rules and the sponsor's
  allowance NOW — so the app learns "taken"/"you have three" before it asks
  anyone to consent — and validates the pointer so it cannot fail later. TTL
  is bounded (reference: 30–600 s, default 300). Refusals are `400 {error,
  code}` with `label_invalid | reserved | name_taken | cap_reached | not_open |
  pointer_invalid`; a missing or wrong token is `403`.
- `POST /api/identity/claim` accepts `voucher` **instead of** a partner token.
  Everything else is unchanged: `pubkey == signer`, the receipt, the label
  rules. The voucher must name exactly this `tld` and `label`; the sponsor
  recorded is the voucher's and a body that names its own is refused; the
  allowance is re-checked **under the row lock**; the voucher is consumed in
  the same transaction as the claim row, so one voucher cannot claim twice and
  a refused claim leaves the voucher unspent; the pointer is written in the
  same request, so the name never exists unpointed; `expires_at` comes from
  the TLD's lending term. Refusals carry `code` (`voucher_rejected`,
  `cap_reached`, `name_taken`, `label_invalid`, `reserved`, `not_open`) beside
  the sentence.
- A voucher is a random token stored **hashed** (like a session token), not
  an HMAC over a server secret: single use needs a row either way, the row
  can hold the binding, and there is then no second secret to provision or
  rotate. Reference: `web/domains/identity.py` `issue_voucher` /
  `claim_with_voucher`, `web/domains/models.py` `ClaimVoucher`.

**What the app's server does** (recommended shape; MyPastebin's):

1. Verify the session (`identity.authenticate`, §5.6): the sponsor is the
   signed-in name's key, never a value the page sent.
2. Ask the registry for the voucher with the app's own records as the
   pointer, and return `{voucher, tld, label, name, voucherExpiresAt, limit,
   held}` to the page. **Never** a key, and no claim from the server.
3. The page calls `names.claim({tld, label, voucher})` and shows
   `{name, expires_at}`; the server's own list (`GET
   /api/identity/partner/names`) is the registry's record afterwards.

**Why the voucher is not a key** (SECURITY.md T1). A voucher cannot claim
anything by itself: the registry still requires a claim signed by the key
being claimed, generated in a vault, after consent the host obtained. A stolen
voucher lets an attacker with their own browser claim *that one label* under
*that sponsor's* allowance for a few minutes — the same thing the sponsor was
about to do — and nothing else. It is therefore held by the page in memory
for the length of one call and is never stored, logged or put in a URL.

Reference implementation: browser `src/apps/handshake-surface.js`
(`namesClaim`, `claimConsentCopy`, `CLAIM_REGISTRY_CODES`),
`src/identity/identity-account.js` (`claimIdentity` with `voucher`,
`issuedBy`, `expiresAt`), `src/apps/handshake-ops.js` (`confirmClaimDialog`);
registry `web/core/api_identity.py` (`partner_voucher`, `claim`); consumer
`pastebin/server/registry.js` (`voucher`, `voucherFor`) and
`pastebin/names-ui.js` (`register`). Tests: browser
`tests/hns/handshake-apps.test.js` (§5.8 block), registry
`domains/tests_voucher_claims.py`, app `test/names.test.js`.

## 6. Record namespaces and cross-app isolation

Two apps on one name must not be able to stomp each other. The rule:

- An app may only add/update/delete records that **match one of its own
  declared `records` shapes** — owner pattern AND type AND value prefix.
  Shapes are the namespace. `2url` declaring `TXT` values with literal
  prefix `redirect=` at owner `@` can never touch `ipfs=…` TXT records at
  the same owner, and vice versa.
- Every DNS-writing shape MUST have a non-empty **literal discriminator**:
  a value prefix of the form `<tag>=` (TXT) or an owner label prefix
  `_<tag>` (other types), where `<tag>` is unique per app id in the host's
  installed set. Hosts MUST refuse to install a manifest whose shapes
  collide with an already-installed app's shapes on an overlapping scope
  (first install wins; the user is told which app owns the tag).
- The tags `ipfs`, `ar`, `hns`, `atproto`, `nostr`, `dane`, plus the
  `MANAGED_PREFIXES`/`MANAGED_TYPES` surfaces, are reserved by the platform
  and grantable only to the first-party flows that already own them
  (pinthis's `ipfs=`/`ar=` shapes are the platform publish pointer — its
  manifest is allowed them precisely because `content.publish` routes
  through the pipeline that owns those records; see the example).
- The mediator additionally keeps a local **provenance ledger** — which app
  wrote which (name, owner, type, value) and when — used for revocation
  (§9) and for the settings UI's "records written by this app" view. The
  ledger is advisory (the user can always edit records in the panel, which
  is sovereign and bypasses app isolation by design); the *shape match* is
  the enforcement.

Honest limitation, stated plainly: cross-app isolation is enforced by the
mediator. The registry only enforces *user*-level scope; it does not know
apps exist. A malicious page that somehow obtained the user's session or a
signed request is bounded by the registry's rules, not by app shapes.
Optional hardening (v0.2 candidate, §12): the registry could accept an
`app` tag in the NIP-98 event and enforce declared shapes server-side.

## 7. Manifest integrity and authorship

App identity is a Handshake name; authorship proof reuses the identity
system rather than inventing a PKI:

1. **The signature.** `signature` carries a BIP-340 signature by the app
   name's control key over the canonicalized manifest (§3), expressed as a
   kind-30078 event (`d` tag `hnsapp:<id>:<manifest_hash>`) — the same
   receipt machinery as claims and atproto bindings, verifiable offline by
   `nostr.py`-equivalent code.
2. **The anchor.** The verifying key is read from the name's `_hns` record
   (`_hns.<label>.<tld>` for issued labels, apex `_hns` TXT for imported
   TLDs — `identity.py record_value` / `control_record_value`), which the
   registry serves and DNSSEC-signs. Verified state is therefore:
   *manifest signature valid* AND *key matches the DNSSEC-anchored `_hns`
   record for `id`*. "Unsigned" zones give the weaker *valid but
   DNS-anchored-unsigned* state; hosts show it as such.
3. **Discovery.** The canonical manifest lives at
   `https://<id>.hns.one/.well-known/hnsapp.json` (and natively at
   `<id>/.well-known/hnsapp.json`), optionally content-addressed via a
   `hnsapp=<cid>` TXT at owner `_app` in the app name's zone so the exact
   bytes are pinnable and the hash is in DNS. Either way the signature is
   what's trusted, not the transport.
4. **Trust states the UI must distinguish** (never collapse):
   - **Verified** — signature checks against the anchored `_hns` key.
   - **Verified, key rotated** — signature checks against a *previous*
     epoch's key. Treat as unverified until re-signed.
   - **Unverified** — no/invalid signature, or no `_hns` anchor. Installable
     only behind an explicit "install unverified app" affordance; dangerous
     capabilities refused (§4.2).
5. **Updates.** A new manifest for an installed id must carry a valid
   signature by the *currently anchored* key and a `app.version` ≥ the
   installed one. Capability/shape additions trigger differential
   re-consent (§8). A signature by a different key than the one the user
   installed under is surfaced as a key change even when the anchor agrees
   (TOFU pinning of the author key, like SSH).

**Registry / directory (sketch, deliberately minimal).** Discovery beyond
"type the name" can be a curated list: a JSON index of `{id, manifest_hash,
reviewed_at}` published at a first-party name, where listing requires a
human security review (capabilities minimal? shapes discriminated? entry
origin owned by the id? redirect/gateway behavior sane?). The curated list
adds *review*, never *authority*: installation trust always reduces to the
manifest signature + `_hns` anchor, so a compromised list can at worst
delist or fail to warn, not impersonate. Un-listed apps remain installable
from their name directly — the system stays permissionless.

## 8. Install, grant, and update lifecycle

- **Install** = fetch manifest → schema-validate → verify signature/anchor →
  check capability registry + shape collisions → show the app's identity,
  verification state, and *full* requested capability list (rendered as
  effects, per name-agnostic templates) → user accepts. Install alone grants
  **no names** — it registers the ceiling.
- **Grant** = per (app id, name), created only through the `names.request`
  picker, the `names.claim` consent (a name the user just agreed to register
  through this app is granted to it in the same act, §5.8), or the settings
  UI. Recorded with the manifest hash it was consented under.
- **Update** = new manifest verified per §7. Capabilities/shapes that are a
  subset of the consented hash apply silently; any broadening shows a diff
  consent ("2url now also asks to: …") and existing grants stay pinned to
  the old hash until accepted.

  **When the host looks** (added in v0.2 after this was found unimplemented and
  unimplementable-by-accident in the reference host). A host **MUST** re-read
  an installed app's manifest — it is not enough to fetch it once at install
  and never again. Without this rule a host satisfies every word above and
  still never applies it: the reference host returned early from discovery for
  any origin already installed, so an app that shipped a new capability was
  permanently frozen at the manifest the user first saw, `version()` kept
  reporting the old set, and the app hid the feature it had just released.
  Normative timing:

  - re-read on page load at an installed entry origin, **rate-limited to once
    per origin per session** (an app that navigates ten times costs one fetch);
  - re-read on an explicit user action — a host **MUST** offer a "check for
    updates" affordance wherever it lists installed apps, and that action
    **MUST** bypass the per-session budget and any refusal made earlier in the
    session, because the person asking is the reconsideration;
  - compare the manifest **hash**; identical bytes are a no-op with no log and
    no prompt.

  **What each outcome does.** Capability additions → the diff consent, worded
  as an *update* and listing **only what is new** (re-reciting what is already
  granted teaches people the list is boilerplate). Accepting re-pins the
  install at the new hash with grants preserved; declining keeps the OLD
  manifest pinned and the refusal is **session-only**, like every other
  refusal. Capability removals or metadata-only changes → apply silently and
  **log**. A new manifest that fails validation, or that no longer lists the
  origin it was served at, → **keep the installed one** and log why: a broken
  deploy of an app must not become a dialog the user cannot act on.

  **Where the user can see it.** A host's installed-apps surface **MUST** show,
  per app, the version it is installed at and what that version may do, in the
  same effect sentences the consent screen used. "Which version did I agree to,
  and to what?" has to be answerable somewhere other than a dialog that has
  already closed.
- **Uninstall / revoke** — §9.

## 9. Revocation

Revoking a grant (one name) or uninstalling (all names) MUST:

1. Immediately stop provider access for that scope (in-flight `propose`
   rejects with `NotGranted`).
2. Offer — not silently perform — cleanup: the mediator enumerates records
   on the affected names matching the app's declared shapes (cross-checked
   against the provenance ledger) and presents a normal consent plan to
   delete them. The user may decline: **records outlive apps by design** — a
   short link keeps redirecting after its management app is gone, because
   the record belongs to the *name*, not the app. This is a feature; the UI
   says so.
3. Leave the name, its keys, and every non-matching record untouched.

Key compromise on the *app author's* side (stolen app-name control key) is
handled by the identity system's epoch bump: hosts re-verify the anchor at
update time and treat epoch changes per §7.4.

## 10. Gateway behavior declarations

Apps whose function depends on how the gateway serves a record declare it in
`gateway.requires`. v0.1 defines one feature beyond the existing baseline:

### 10.1 Baseline (id `one.hns.gateway.content.v1`)

`ipfs=<cid>` / `ar=<txid>` TXT at a label → gateway serves the content
(IPFS wins over Arweave; `pointer_for` in gateway.py). `.well-known`
identity endpoints outrank published content unconditionally.

### 10.2 `one.hns.gateway.redirect.v1`

**The record.** One TXT at the label being redirected:

```
<label>  TXT  "redirect=<absolute-url>[;code=301|302|307|308][;path=drop|append]"
```

- `redirect=` value grammar: `https://` URL only in v1 (no `http:`,
  `javascript:`, `data:`, no userinfo `user:pass@`, no literal IP hosts, no
  whitespace/control chars; ≤ 480 bytes so the whole value passes the
  registry's TXT validator and still fits comfortably). Targets whose host
  is the gateway base itself (`*.hns.one`) or a Handshake name are allowed —
  loops are handled by the client's redirect limit plus the gateway's own
  self-target check below.
- `code` default `302`. `301`/`308` are cacheable commitments; UIs should
  default to 302 and say why.
- `path` default `drop` (the short link is exact). `append` joins the
  request path+query onto the target for prefix-forwarding use.
- **Exactly one** `redirect=` TXT per owner is valid; the gateway MUST
  treat two as a configuration error and serve the error page rather than
  picking one (the `publish_identity_record` "one record per owner" rule,
  same reason: half-cached wrong answers are indistinguishable from
  working).

**Serving contract.** In `do_GET`, for a resolved (zone, label):

1. `/.well-known/*` and `/_gateway/*` are answered first, exactly as today —
   a redirect record MUST NOT be able to move identity endpoints
   (`nostr.json`, `atproto-did`, `did.json`). This is load-bearing: a
   redirect that captured `atproto-did` would hijack handle verification.
2. Then, if a **valid** `redirect=` TXT exists at the label: respond with
   the declared code and `Location`, `Referrer-Policy: no-referrer` (already
   global), `Cache-Control: public, max-age=300` (regardless of code — the
   record can change), `X-Robots-Tag: noindex`, and **no body content from
   the record** other than a minimal text line. A malformed value is
   *ignored with a logged warning* (the `pointer_for` malformed-pointer
   convention) and serving falls through to content.
3. `redirect=` outranks `ipfs=`/`ar=` at the same owner. Deterministic
   precedence, so writers can reason; the *mediator* is responsible for
   warning when a redirect is written over a live publish pointer (the
   `NeedsConfirm`-style check: "this name has a published site; the redirect
   will shadow it").
4. **Safe-redirect handling.** The redirect is the *name holder's own*, on
   their own name — the same authority they'd have pointing an A record
   anywhere — so v1 does not interstitial by default. Required mitigations
   instead: the target grammar above (no scheme downgrade, no userinfo
   tricks); `no-referrer`; a self-target check (a redirect whose target
   resolves to the same zone+label serves the error page, killing 1-hop
   loops; browsers bound longer loops); and gateway support for an operator
   **denylist** (serve 410 + an abuse note for names reported for phishing —
   the same operator lever as unpublishing). Hosts MAY additionally show a
   first-visit interstitial for redirects leaving the Handshake namespace;
   the standard permits, does not require, it.

**Browser-native behavior.** A Wildroot resolving `foo.2url` natively (not
via the gateway) SHOULD honor the same record with the same precedence,
so the link works identically on and off the mirror.

## 11. What exists today

**Wildroot (desktop browser), the reference host:**
- Manifest discovery at `<origin>/.well-known/hnsapp.json` (falling back to
  `<origin>/manifest/<label>.app.json`), schema validation, install, the grant
  store, and the update checks of §8.
- The `window.handshake` provider, injected only into an installed app's
  `ui.entry` origins (a single origin or a D5 list), with `version`,
  `names.primary`, `names.list`, `names.request` (the picker of §5.2),
  `names.claim` (§5.8), `identity` (§5.5) and `auth.token` (§5.6).
- The error codes and logging of §5.7.
- `records.get`, `records.propose` and `content.publish` answer `OutOfScope`.
- Manifest signatures (§7) are not checked: every install is unverified and
  shown with a warning. Consent prompts other than the name picker are native
  dialogs, not the main-owned overlay §5.4 describes.

**hns.one gateway:** serves `one.hns.gateway.content.v1` and
`one.hns.gateway.redirect.v1` (§10) and advertises both at `/_gateway/features`
on each name's host.

**HNS.ONE registry:** NIP-98-signed DNS mutations, claims and publishing
(`/api/publish`), and the voucher flow of §5.8
(`POST /api/identity/partner/voucher`, `voucher` on `POST /api/identity/claim`).

**Apps:** `.pxls` uses `identity.authenticate` (still under the extension id
`one.hns.auth.nip98`, which hosts accept interchangeably). MyPastebin uses
`identity.authenticate` and `names.claim`. `2url` and `pinthis` run only as
first-party browser pages (`wildroot://2url`, `wildroot://publish`); their
manifests in `examples/` describe the contract those pages follow.

**Not built:** manifest signing and the `_hns` anchor check (§7), the
provenance ledger (§6), schema-template expansion and shape enforcement for
`records.propose`, and server-side shape enforcement in the registry.

## 12. Open questions

1. **Server-side shape enforcement (v0.2?).** Should the registry learn an
   `app` NIP-98 tag and enforce declared shapes, so cross-app isolation
   survives a compromised mediator? Costs: manifests (or shape digests)
   registered server-side; a second copy of the shape matcher.
2. **`2url` claim pricing.** Free labels under `2url` like the `14898`
   registry, or a paid tier? The claim flow supports free only today;
   paid claiming is a billing design this spec deliberately leaves out.
3. **Interstitial policy.** §10.2 makes the leaving-Handshake interstitial
   optional. Ship it on by default in Wildroot, or trust `no-referrer` +
   denylist? (Phishing via shortener is the top abuse channel — SECURITY.md
   T10.)
4. **Unverified apps.** Allow install-with-warning (current draft), or
   refuse outright until signed? Refusing is safer and cheap while the
   ecosystem is size zero; the draft allows it to keep the system
   permissionless.
5. **`path=append` in v1?** Prefix-forwarding doubles the redirect record's
   utility but widens the phishing surface (attacker-controlled suffixes on
   a trusted-looking short domain). Could ship v1 as `drop`-only.
6. **Tag registry.** §6's per-host first-install-wins tag collision rule is
   local; two hosts can assign the same tag to different apps. A global tag
   claim (a TXT at the app's own name: `hnsapp-tag=<tag>`) would make tags
   name-anchored like everything else. Worth the machinery?
7. **Grant portability.** Grants live in the browser profile. Should they
   ride in the vault export (they are preferences, not secrets — but losing
   them on restore is friction)?
8. **Per-app SCOPED DELEGATED key (v0.2+ hardening, design-only).**
   `identity.authenticate` (§5.6) is safe because the mediator holds the origin
   ceiling and signs one request at a time — but every token is still a signature
   by the name's *full* control key, minted in main on demand. A stronger shape
   would issue each installed app a **scoped delegated key**: a fresh keypair the
   mediator generates, records as a delegation of the name (a receipt naming the
   app id + the allowed origin + an expiry), and lets the app's server verify
   against — so a mediator bug or a coerced sign path could at worst spend a
   narrow, expiring, per-app credential rather than reach the control key at all.
   This composes with the identity system's existing delegation model
   (`exportDelegation` already separates "run this name" from "be this person")
   and needs no new signature format — the receipt is another kind-30078 event.
   Deliberately NOT built in v0.1/v0.2: the origin-checked, ephemeral,
   consent-at-install token is sufficient for `.pxls`, and a delegated-key
   registry is real machinery (issuance, rotation, revocation, server-side
   verification of the delegation chain) that should wait for a second app that
   needs it. Noted here so the door stays open by construction.
