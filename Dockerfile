ARG REGISTRY="docker.io/library"
ARG BUILD_IMAGE="python"
ARG BUILD_TAG="3.12-trixie"
ARG BASE_IMAGE="python"
ARG BASE_TAG="3.12-slim-trixie"

FROM $REGISTRY/$BUILD_IMAGE:$BUILD_TAG AS builder
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DISABLE_PIP_VERSION_CHECK=yes
ARG PIP_CERT
ARG PIP_CLIENT_CERT
ARG PIP_TRUSTED_HOST
ARG PIP_INDEX_URL
ARG PIP_EXTRA_INDEX_URL
ARG GIT_BRANCH_NAME
ARG UV_DEFAULT_INDEX
ARG UV_INDEX_URL
ARG UV_INSECURE_HOST
ENV UV_PROJECT_ENVIRONMENT=/usr/local

COPY debian.txt /tmp/src/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/src/debian.txt | tr "\n" " ") && \
    rm -rf /tmp/src/debian.txt /var/lib/apt/lists/*

COPY ./ /tmp/src
RUN pip install uv

WORKDIR /tmp/src
RUN uv sync --frozen --no-editable
RUN uv pip install --system hatchling hatch-vcs
RUN uv build . --out-dir /tmp/
RUN uv pip uninstall --system azul-plugin-mobile-evasion
RUN uv pip install --system --no-deps --find-links /tmp/ azul-plugin-mobile-evasion==$(hatchling version)

RUN if [ -n "$UV_INDEX_URL" ]; then \
    if [ "$GIT_BRANCH_NAME" = "refs/heads/dev" ]; then \
    uv pip freeze | grep 'azul-.*==' | grep -v '^azul-plugin-mobile-evasion' | cut -d "=" -f 1 | xargs -I {} uv pip install --extra-index-url=$UV_INDEX_URL --system --upgrade --no-deps --prerelease allow '{}>=0.0.0-dev'; \
    else \
    uv pip freeze | grep 'azul-.*==' | grep -v '^azul-plugin-mobile-evasion' | cut -d "=" -f 1 | xargs -I {} uv pip install --extra-index-url=$UV_INDEX_URL --system --upgrade --no-deps '{}>=0.0.0'; \
    fi; \
    fi

FROM $REGISTRY/$BASE_IMAGE:$BASE_TAG AS base
ENV DEBIAN_FRONTEND=noninteractive
COPY debian.txt /tmp/src/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/src/debian.txt | tr "\n" " ") && \
    rm -rf /tmp/src/debian.txt /var/lib/apt/lists/*
ARG UID=21000
ARG GID=21000
RUN groupadd -g $GID azul && useradd --create-home --shell /bin/bash -u $UID -g $GID azul
USER azul
COPY --from=builder /usr/local /usr/local

FROM base AS tester
ENV FILE_MANAGER_AZURE_BLOB_CACHE_ENABLED=false
ENV PIP_DISABLE_PIP_VERSION_CHECK=yes
ARG PIP_CERT
ARG PIP_CLIENT_CERT
ARG PIP_TRUSTED_HOST
ARG PIP_INDEX_URL
ARG UV_DEFAULT_INDEX
ARG UV_INDEX_URL
ARG UV_INSECURE_HOST
ARG PIP_EXTRA_INDEX_URL
USER root
COPY ./pyproject.toml ./pyproject.toml
RUN uv pip install --system --group dev
USER azul
ENV PATH="/home/azul/.local/bin:$PATH"
COPY --chown=azul ./tests /tmp/tests
RUN pytest -o cache_dir=/tmp/cache --tb=short /tmp/tests
RUN touch /tmp/testingpassed

FROM base AS release
COPY --from=tester /tmp/testingpassed /tmp/
ENTRYPOINT ["azul-plugin-mobile-evasion"]
