# syntax=docker/dockerfile:1
FROM python:3.12-slim

ARG TRIVY_VERSION=0.75.0
ARG INSTALL_SEMGREP=true
# CodeQL is the primary SAST engine (~600 MB bundle). Check GitHub's CodeQL terms for private code.
ARG INSTALL_CODEQL=true
ARG TARGETARCH

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data LOG_JSON=true CODEQL_PATH=/opt/codeql/codeql

# git: cloning; nodejs/npm: lockfile refresh + JS syntax checks; trivy: SCA/secrets/IaC.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl nodejs npm \
 && case "${TARGETARCH:-amd64}" in arm64) TA=ARM64 ;; *) TA=64bit ;; esac \
 && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TA}.tar.gz" \
    | tar -xz -C /usr/local/bin trivy \
 && if [ "$INSTALL_CODEQL" = "true" ]; then \
      case "${TARGETARCH:-amd64}" in \
        arm64) echo "CodeQL bundle is x64-only; skipping" ;; \
        *) curl -fsSL https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz \
             | tar -xz -C /opt ;; \
      esac; \
    fi \
 && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt bandit \
 && if [ "$INSTALL_SEMGREP" = "true" ]; then pip install semgrep; fi

COPY remediation ./remediation
COPY pyproject.toml README.md ./

RUN useradd --create-home --uid 10001 app && mkdir -p /data && chown app:app /data
USER app
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4).status==200 else 1)" || exit 1

CMD ["uvicorn", "remediation.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
