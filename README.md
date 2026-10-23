# Handshake Apps

A proposed standard for web apps that sign people in with a Handshake name
they already hold. The app declares what it needs in a manifest. The browser
holds the keys, asks the user, and gives the app only public data or a
signature bound to the app's own origin.

## Status

Validate bundled examples with `python -m pip install jsonschema` followed by
`python scripts/validate.py`. This checks the JSON Schema and URI formats;
it does not verify signatures, capability semantics or browser integration.

Draft, version 0.2. The [Wildroot](https://wildroot.io) browser implements
install, grants and the `window.handshake` provider with names, identity,
sign-in tokens and voucher-backed name registration. Record writes and
publishing through the provider are specified but not implemented, and
manifest signatures are not checked yet. Two apps use it,
[.pxls](https://pxls.hns.one/) and [MyPastebin](https://mypastebin.hns.one/),
both by the author of this standard. Section 11 of the specification lists
what exists.

## Contents

| File | What it is |
|---|---|
| [`HANDSHAKE-APPS.md`](HANDSHAKE-APPS.md) | The specification: roles, the manifest, capabilities, and the `window.handshake` contract |
| [`SECURITY.md`](SECURITY.md) | The threat model, which is normative |
| [`V0.2-DELTA.md`](V0.2-DELTA.md) | The changes deploying `.pxls` required, now folded into the specification |
| [`manifest.schema.json`](manifest.schema.json) | JSON Schema (2020-12) for a manifest |
| [`examples/`](examples/) | Manifests for `2url` and `pinthis`, two first-party browser pages |

## Example

A manifest that asks only to sign the user in, served at
`https://example.hns.one/.well-known/hnsapp.json`:

```json
{
  "manifest_version": 1,
  "id": "example",
  "app": { "name": "Example", "version": "1.0.0", "author": { "name": "You", "handshake": "example" } },
  "tlds": [],
  "capabilities": [
    { "cap": "identity.authenticate", "scope": "any-held-name", "reason": "Sign you in with your name." }
  ],
  "ui": { "entry": "https://example.hns.one/" }
}
```

On that page, once the browser has injected `window.handshake` (it can arrive
after the page's scripts run; see section 5.1):

```js
const { name } = await window.handshake.names.request({})
const url = 'https://example.hns.one/api/session'
const token = await window.handshake.auth.token({ url, method: 'POST', name })
await fetch(url, { method: 'POST', headers: { Authorization: token } })
```

The token is a NIP-98 header signed by the name's control key. The app's
server must verify it against the name's `_hns` record (section 5.6).

## License

MIT, see [`LICENSE`](LICENSE).
