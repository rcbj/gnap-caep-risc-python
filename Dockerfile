# syntax=docker/dockerfile:1
FROM python:3.11-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE VERSION ./
COPY src src
RUN pip install --no-cache-dir .

FROM python:3.11-slim
WORKDIR /app
COPY --from=build /usr/local /usr/local
COPY demo demo
COPY scripts scripts
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
EXPOSE 3000
ENV PORT=3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz'%os.environ.get('PORT','3000')).read()" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "demo/app.py"]
