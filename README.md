# Handshake Apps

**A community standard for name-driven applications.** A Handshake App is an
ordinary web app served from a Handshake name that asks the *browser* — not a
platform — who the user is. People sign in with a name they already hold: no
account, no password, no OAuth redirect, and no key ever leaves the browser.

This repository is the specification, its JSON Schema, and worked examples.
It is implementation-independent: any Handshake-aware browser can be the
mediator, and any web app can be a client.

## Contents

| File | What it is |
|---|---|
| [`HANDSHAKE-APPS.md`](./HANDSHAKE-APPS.md) | The standard — roles, the manifest, the capability model, and the `window.handshake` mediation contract. |
| [`SECURITY.md`](./SECURITY.md) | The threat model the design is built against. |
| [`V0.2-DELTA.md`](./V0.2-DELTA.md) | The v0.2 delta — what a real deployed app (`.pxls`) needed that v0.1 lacked, including `identity.authenticate`. |
| [`manifest.schema.json`](./manifest.schema.json) | JSON Schema for an app manifest. |
| [`examples/`](./examples/) | Real manifests (`2url`, `pinthis`). |

## The idea in one paragraph

An app declares, in a static manifest, the capabilities it wants — read the
user's main identity, prove control of a name to the app's own server, write a
record to a name the user owns. The browser is the mediator: it holds the
keys, shows the user what an app asked for, and hands back only public data or
a single-use signature bound to the app's own origin. The manifest is a
ceiling the app can never exceed, and the browser can never be turned into a
signing oracle for someone else's endpoint. Least privilege, statically
declared, enforced by the one party the user already trusts to hold their keys.

## Status

The standard is implemented end-to-end in the HNS.ONE / Wildroot browser, and
[`.pxls`](https://pxls.hns.one) is the first third-party app built against it —
it signs players in with a Handshake name and verifies that identity on its own
server. `identity` (read the main name) and `identity.authenticate` (a NIP-98
attestation to the app's own origin) are the two capabilities in production
today; the record-mutation and content-publish capabilities are specified and
partially built.

## Contributing

Proposals and critiques are welcome as issues and pull requests. A change to
the contract should say what real app needs it and what it costs in trust —
`V0.2-DELTA.md` is the model.

## License

MIT — see [`LICENSE`](./LICENSE).
