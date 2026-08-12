FROM python@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6

LABEL org.opencontainers.image.title="Causure OpenAI-compatible quota core" \
      org.opencontainers.image.version="0.4.0a18" \
      org.opencontainers.image.vendor="Causure contributors"

ENV HOME=/tmp \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG CAUSURE_WHEEL_SHA256

COPY dist/causure-0.4.0a18-py3-none-any.whl /wheels/
COPY build/quota-pilot/wheels/waitress-3.0.2-py3-none-any.whl /wheels/

RUN test -n "$CAUSURE_WHEEL_SHA256" \
    && python -I -c "import hashlib,pathlib,sys; p=pathlib.Path('/wheels/causure-0.4.0a18-py3-none-any.whl'); assert hashlib.sha256(p.read_bytes()).hexdigest() == sys.argv[1]" "$CAUSURE_WHEEL_SHA256" \
    && python -I -c "import hashlib,pathlib; p=pathlib.Path('/wheels/waitress-3.0.2-py3-none-any.whl'); assert p.stat().st_size == 56232; assert hashlib.sha256(p.read_bytes()).hexdigest() == 'c56d67fd6e87c2ee598b76abdd4e96cfad1f24cacdea5078d382b1f9d7b5ed2e'" \
    && python -m pip install --disable-pip-version-check --no-cache-dir --no-deps --no-index \
       /wheels/waitress-3.0.2-py3-none-any.whl \
       /wheels/causure-0.4.0a18-py3-none-any.whl \
    && python -I -c "import importlib.metadata as m; assert m.version('causure') == '0.4.0a18'; assert m.version('waitress') == '3.0.2'" \
    && rm -rf /wheels \
    && mkdir -p /var/lib/causure \
    && chown 65532:65532 /var/lib/causure

USER 65532:65532
WORKDIR /tmp
EXPOSE 8080
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-I", "-c", "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=2); raise SystemExit(0 if r.status == 200 else 1)"]

ENTRYPOINT ["causure"]
CMD ["openai-quota-serve", "/run/configs/openai-quota-host.json"]
