# Echo — ask your phone system

Echo reads what a phone system actually recorded — SIP signalling, registrations,
trunks, call detail — and answers in plain language. No query syntax, no
dashboard to learn: *"any problems?"*, *"who's talking?"*, *"calls today?"*.

This repository is the site at [echo.echoguard.ca](https://echo.echoguard.ca)
and the connector that feeds it. **Echo is integrated into
[AiPBX](https://github.com/shido6/AiPBX)**, the open-source IP PBX: inside that
portal it is the **AI → Echo** module, not a separate product.

## What is in here

| Path | What it is |
|---|---|
| `index.html` | the landing page |
| `app.html` | the Echo interface — ask a question, read the answer |
| `login.html` | beta sign-in |
| `manage.html` | management view for connected phone systems |
| `admin.html` | admin console: users, allow/block lists, rate limits |
| `greg.html`, `reach.js` | the "Reach Greg" visitor call page and its browser client |
| `assist.html` | Live Assist — when a human has to take the call |
| `forge.html` | Forge — build your own voice AI on the same pipeline |
| `relay.html` | Relay — the phone system, covered |
| `funding.html`, `support/` | funding and support pages |
| `connector/` | the on-premises connector: installer, agent, capture examples, build script |
| `music/` | hold music used by the demo line |

Everything served to a browser is plain HTML, CSS and JavaScript — no build
step, no framework. The pages call `/api/*`, which the deployment proxies to the
Echo backend (not part of this repository; see below).

## The connector

`connector/connect.sh` is a self-contained installer. It points a phone system's
copy of its own signalling (HEPv3 — signalling only, never audio) at a small
helper on loopback, and the helper forwards it to Echo over TLS.

```sh
curl -fsSL https://echo.echoguard.ca/connector/connect.sh | bash -s -- --dry-run
curl -fsSL https://echo.echoguard.ca/connector/connect.sh | bash -s -- 'EC-<id>.<key>'
curl -fsSL https://echo.echoguard.ca/connector/connect.sh | bash -s -- --uninstall
```

The security model is chain of custody: every embedded file is hash-pinned in
the installer and re-checked against `manifest.json` before anything is written,
nothing is fetched from a third party, every touched file is backed up, and
`--uninstall` removes exactly what it added. Example capture configurations for
Asterisk, FreePBX, FreeSWITCH and Kamailio live in `connector/examples/`.

`connector/build.py` regenerates `connect.sh` and `manifest.json` from
`connector.py` plus the examples. Run it after changing either.

## Echo inside AiPBX

In AiPBX the module lives under **AI → Echo** in the portal. It is read-only: it
links Sipfront SIP test runs to this server's own capture, registrations and
trunks, so Greg — the portal's AI VoIP engineer — answers with evidence instead
of a guess. Nothing on that page changes the PBX. See
[docs/cloud-ai.md](https://github.com/shido6/AiPBX/blob/main/docs/cloud-ai.md)
in the AiPBX repository.

## Running the site locally

Any static file server works; the paths are relative:

```sh
python3 -m http.server 8000
```

Then open <http://localhost:8000/>. Pages that call `/api/*` need the backend
proxied to answer.

## What is not in this repository

The Echo backend — sign-in, the question-to-query planner and the answer
renderer served behind `/api/*` — is not published here. The pages are useful
without it; the queries are not.

## Author

Built by **Gregory Merriweather** ([kaiel@echoguard.ca](mailto:kaiel@echoguard.ca),
GitHub [@shido6](https://github.com/shido6)): the Echo interface and site, the
hash-pinned connector, and **the Echo integration into AiPBX** — the AI → Echo
module, the HEP capture and correlation assistance, and the documentation that
ships with it.

## License

MIT — see [LICENSE](LICENSE).
