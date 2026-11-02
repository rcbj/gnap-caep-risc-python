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

`python3 scripts/live_iya_sts.py` runs the install script in a scratch copy of this checkout (it writes the `tlsCa` chain), then builds the demo image (which carries the chain), starts it with `TLS_CA_REFRESH=0` and no CA mount, signs in to iya-sts, and checks a credential-change event and a session-revoked event on `GET /live-status`. The nightly workflow runs the unit suite and that script once every 24 hours. Its default ports are 18542 (iya-sts) and 18642 (demo); it refuses 3000, 8081 and 18481-18495. Push CI stays the unit suite.

## Layout

- `src/gnap_caep_risc/` the client, key proofs (mtls, httpsig, jwsd), and `ssf/` (one poll stream)
- `tests/` config, subject, client, the Shared Signals receiver, and `test_trust_chain.py` (the install script writes the whole chain to `tlsCa`'s path; the library trusts an HTTPS server through that file)
- `demo/app.py` the HTTP demo; `demo/gnap.json` the sample configuration
- `scripts/configure_iya_sts.py` registers the app and writes the listener CA trust chain to the file `tlsCa` names; `scripts/trust_chain.py` holds `save_trust_chain()` and refreshes that file; `scripts/redirects.py` supports it

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/gnap.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library adds every certificate in it to the default trust store.

`scripts/configure_iya_sts.py`, the install script, writes that file. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`. The client key and certificate stay out of the image; compose mounts `demo/generated` for them. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The mechanism is `COPY demo demo` plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, BuildKit fails on the missing `demo/generated` and the classic builder fails with "no source files were specified". A directory COPY of `demo/` (which always exists) succeeds in both.

The container entrypoint also refreshes the file from the authorization server at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python scripts/trust_chain.py --config demo/gnap.json` refreshes it by hand.

## Demo

`PORT` defaults to 3000 and is the bind port. Loopback redirect and finish URLs follow `PORT`. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. `GET /healthz` returns `ok`. `GET /live-status` reports whether this process is signed in and the Shared Signals events it has accepted, without tokens. `ssf.pollIntervalMs` is a millisecond interval. Do not bind port 3000 or 8081 while something else is already using them.

## Signals

Omitted or `true` keeps CAEP and RISC on, and the resolved configuration omits `signals`. `false` does not start the receiver, does not require transmitter metadata, drops `ssf.read` and `ssf.manage`, and is kept on the resolved configuration. Anything else raises `signals must be true or false`.

## License

MIT. Copyright (c) 2026 Iya CyberSecurity Solutions, LLC.

`develop` and `main` must be the same commit. A pull request merged into `main` publishes the package to PyPI after the test workflow succeeds on that commit. A direct push does not. There is no API token: PyPI Trusted Publishing trades the workflow's GitHub OIDC token for a short-lived upload token, from the `pypi` environment, and PyPI holds the publisher for this repository and `publish.yml`. A version already on PyPI stays there; the next release is a new `version` in `pyproject.toml` (and `VERSION`).
