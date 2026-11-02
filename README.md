# gnap-caep-risc

A server-side [GNAP](https://www.rfc-editor.org/rfc/rfc9635) client. The key is registered by value and proved with mutual TLS, an HTTP message signature, or a detached JWS. Access tokens are key-bound; a bearer token is refused. One Shared Signals poll stream carries CAEP and RISC events.

The private key stays in this process. The same `gnap.json` shape as the Node library loads: the JSON keys are identical.

## Build and tests

```bash
docker build --target test .
```

The `test` stage runs `pip install --no-cache-dir ".[dev]" && pytest` in `python:3.11-slim`. GitHub Actions on a push uses that command. Do not run pytest on the host. The demo image does not run the suite.

Those tests use an in-process stub. They do not start iya-sts.

`python3 scripts/live_iya_sts.py` is the live half. It builds this demo image, registers it with iya-sts, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. When `IYA_STS_URL` is unset it starts the latest main branch of iya-sts in memory mode, with persistence and clustering off. It uses the host's Python and Docker and does not import this library. It binds two high ports and never binds 3000 or 8081. The nightly workflow runs the unit suite and this script once every 24 hours.

PyPI publishing is not set up yet.

## Three calls

```python
from gnap_caep_risc import GnapClient

gnap = GnapClient.from_file("gnap.json")
started = gnap.request_grant()
done = gnap.finish_redirect(query, [started.pending.id])
```

`request_grant` returns a redirect and a pending grant. `finish_redirect` checks the interaction hash against grants this process started, then continues the grant with the key proof. Pass the pending ids this browser was given as `allowed_ids`.

`resolve_config` and `read_config_file` load the same document without starting a grant.

## Signals

`signals` omitted or `true` keeps CAEP and RISC on. The resolved configuration omits the key, fills `ssf` from `ssf.transmitter` or `transmitterIssuer`, and asks for `ssf.read` and `ssf.manage` when `access` does not say otherwise.

`signals: false` does not start the Shared Signals receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the GNAP access. The resolved configuration includes `signals: false`. If those two rights were the only ones, configuration fails and asks for another right the authorization server grants. Any other value fails with `signals must be true or false`.

`ssf.pollIntervalMs` is the poll interval in milliseconds.

## Demo

```bash
docker compose up --build
```

`PORT` defaults to 3000 and is the bind port. Loopback finish and display URLs follow `PORT`. Any other host is left as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. The home page has a sign-in control; `/login` starts a grant, `/callback` finishes it, and `POST /logout` signs out. `GET /live-status` is JSON: `signedIn`, `subject`, the receiver state, and the Shared Signals events this process has accepted (`type` and `jti` only). It does not include tokens. Do not bind port 3000 or 8081 while something else is already using them.

The shipped `demo/gnap.json` leaves `signals` on by omitting the key. Key material is `file:` or `env:` and is not in the tree. Generate a key inside the demo image, then register the application:

```bash
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  gnap-caep-risc-python-demo \
  gnap-caep-risc generate-key --config demo/gnap.json
ADMIN_API_CLIENT_SECRET=… python scripts/configure_iya_sts.py --config demo/gnap.json
```

`--dry-run` prints the admin API calls and sends nothing. When the `gnap-demo` container is running, its `PORT` wins over the shell `PORT`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.
