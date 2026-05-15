# Pinned to bookworm: Debian 13 (trixie) dropped openjdk-17-* in favour of 21,
# and Ghidra 11.2's documented baseline is JDK 17 — pinning here keeps the
# package name stable and matches the README's setup steps.
FROM python:3.12-slim-bookworm

# System deps:
#   gcc / gcc-multilib  → method=transpile (compile.py invokes `gcc -S -m32`)
#   openjdk-17-jdk-...  → required by Ghidra 11.x (drives the decompiler)
#   curl / unzip        → fetch + extract the Ghidra release tarball
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc gcc-multilib \
      openjdk-17-jdk-headless \
      curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pin the Ghidra version in one place so the URL, install dir, and the
# GHIDRA_INSTALL_DIR exported to pyghidra stay in sync. Bump GHIDRA_RELEASE
# (the build tag) and GHIDRA_VERSION_DATE (the dated artifact name) together
# from https://github.com/NationalSecurityAgency/ghidra/releases.
ARG GHIDRA_RELEASE=11.2.1_build
ARG GHIDRA_VERSION_DATE=11.2.1_PUBLIC_20241105
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_11.2.1_PUBLIC

RUN curl -fsSL -o /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_RELEASE}/ghidra_${GHIDRA_VERSION_DATE}.zip" \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip \
    && test -d "${GHIDRA_INSTALL_DIR}"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
