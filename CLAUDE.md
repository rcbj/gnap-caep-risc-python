# gnap-caep-risc

Server-side GNAP client. Import `gnap_caep_risc`. The public class is `GnapClient`.

```python
gnap = GnapClient.from_file("gnap.json")
started = gnap.request_grant()
done = gnap.finish_redirect(query, [started.pending.id])
```

`resolve_config` and `read_config_file` load the same JSON keys as the Node library. Methods are snake_case.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `pip install --no-cache-dir ".[dev]" && pytest` in `python:3.11-slim`. GitHub Actions on a push uses that command. Do not run pytest on the host. The demo image does not run the suite.

Tests use an in-process stub on 127.0.0.1. They do not start iya-sts.

`python3 scripts/live_iya_sts.py` signs the demo in to iya-sts and checks a credential-change event and a session-revoked event on `GET /live-status`. The nightly workflow runs the unit suite and that script once every 24 hours. It does not bind port 3000 or 8081. Push CI stays the unit suite.

## Layout

- `src/gnap_caep_risc/` the client, key proofs (mtls, httpsig, jwsd), and `ssf/` (one poll stream)
- `tests/` config, subject, client, and the Shared Signals receiver
- `demo/app.py` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app; `scripts/redirects.py` and `scripts/trust_chain.py` support it

## Demo

`PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `GET /live-status` reports whether this process is signed in and the Shared Signals events it has accepted, without tokens. `ssf.pollIntervalMs` is a millisecond interval. Do not bind port 3000 or 8081 while something else is already using them.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else raises `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit.
