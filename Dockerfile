# syntax=docker/dockerfile:1
# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM python:3.11-slim AS test
WORKDIR /src
COPY pyproject.toml README.md LICENSE VERSION ./
COPY src src
COPY tests tests
COPY scripts scripts
COPY demo/gnap.json demo/gnap.json
RUN pip install --no-cache-dir ".[dev]" && pytest

FROM python:3.11-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE VERSION ./
COPY src src
RUN pip install --no-cache-dir .

FROM python:3.11-slim
WORKDIR /app
COPY --from=build /usr/local /usr/local
COPY scripts scripts
# The demo, and with it tlsCa's file: demo/generated/idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py saved. The image trusts
# that iya-sts with no bind mount and no fetch. Rebuild after running the
# install script against a different iya-sts.
# .dockerignore admits that one file from demo/generated (never the client key
# or certificate). A COPY of the demo DIRECTORY succeeds with or without it,
# so a fresh clone and CI still build; naming the file, or a glob that
# matches nothing, fails the build in both builders.
COPY demo demo
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz'%os.environ.get('PORT','3000')).read()" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "demo/app.py"]
