#!/usr/bin/env bash
#
# Installs the system-level tools Windows Artifact Analysis needs:
# python3-libscca (Prefetch — src/lib/windows-artifacts/prefetch-parse.py),
# libfsntfs/pyfsntfs ($MFT — mft-parse.py), libesedb/pyesedb (SRUDB.dat —
# srum-parse.py, and now also Windows.edb — search-parse.py), and a Python
# venv with regipy[full]/LnkParse3/olefile/bits_parser/minidump (registry
# hives, LNK, Jump Lists, Shellbags, $UsnJrnl:$J, BITS queue files, and
# WER crash dumps). bits_parser and minidump are both pure-Python/MIT, no
# C build needed — same venv as everything else here, not the system
# python3.
#
# Unlike deploy/install-system-deps.sh (PCAP/RAM Analysis's equivalent),
# which ships from the Enterprise overlay because those are overlay
# features, this lives in Core because Windows Artifact Analysis is a
# Core feature — so it has to run on every plain Core update too, not
# only when an overlay is applied. Called from:
#   - deploy/provision.sh, for a fresh image/first boot.
#   - deploy/forensicator-update.sh's do_install(), on every Core update,
#     so an already-deployed instance picks up these deps the first time
#     it updates to a Core version that introduced them. provision.sh
#     itself never runs again after first boot — without this call from
#     the update path too, every already-deployed instance (overlay or
#     not) would silently keep failing every Prefetch/registry/LNK/Jump
#     List/Shellbag upload forever after updating in place, since nothing
#     else ever installs these.
#
# Idempotent — safe to call on every provision/update.
#
# Usage (as root):
#   APP_DIR=/opt/forensicator SERVICE_USER=forensicator ./install-winartifacts-deps.sh

set -euo pipefail

APP_DIR="${APP_DIR:?Set APP_DIR to the application directory}"
SERVICE_USER="${SERVICE_USER:-forensicator}"

# Debian/Ubuntu's packaged python3-libscca is a single frozen snapshot
# (20200717 as of writing) that distros never update — libyal libraries
# aren't security-sensitive enough to get backports. libscca didn't add
# Prefetch format version 31 (Windows 11 — confirmed directly against
# libyal's own format spec and the "Worked on format version 31 support"
# commit, 2024-11-18) until years after that snapshot, so the distro
# package can NEVER read a Windows 11 Prefetch file — every single one
# fails with "unsupported format version", not an occasional edge case.
# Built from source instead, pinned to a specific known-good release
# (sha256-verified) rather than tracking upstream's latest unpredictably.
LIBSCCA_VERSION="20260527"
LIBSCCA_URL="https://github.com/libyal/libscca/releases/download/${LIBSCCA_VERSION}/libscca-alpha-${LIBSCCA_VERSION}.tar.gz"
LIBSCCA_SHA256="5fa8a3ab602b4431e75e61f4d21ebd46174c524a79173f8c0eadca24cddbdc16"

installed_pyscca_version="$(python3 -c "import pyscca; print(pyscca.get_version())" 2>/dev/null || echo 0)"
if [[ "$installed_pyscca_version" < "$LIBSCCA_VERSION" ]]; then
  echo "==> Building libscca ${LIBSCCA_VERSION} from source (Windows Artifact Analysis Prefetch dependency — installed pyscca is ${installed_pyscca_version}, too old for Windows 11 Prefetch files)"
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config python3-dev python3-setuptools

  # Remove the distro package first — apt and `make install` both target
  # system-wide dist-packages paths, and leaving both in place makes
  # which one `import pyscca` actually resolves an unforced, fragile
  # guess rather than a guaranteed outcome.
  if dpkg -s python3-libscca >/dev/null 2>&1; then
    apt-get purge -y python3-libscca libscca1t64 libscca1 2>/dev/null || apt-get purge -y python3-libscca
  fi

  libscca_build_dir="$(mktemp -d)"
  trap 'rm -rf "$libscca_build_dir"' EXIT
  curl -fsSL -o "${libscca_build_dir}/libscca.tar.gz" "$LIBSCCA_URL"
  echo "${LIBSCCA_SHA256}  ${libscca_build_dir}/libscca.tar.gz" | sha256sum -c -
  tar -xzf "${libscca_build_dir}/libscca.tar.gz" -C "$libscca_build_dir"
  (
    cd "${libscca_build_dir}/libscca-${LIBSCCA_VERSION}"
    ./configure --enable-python
    make -j"$(nproc)"
    make install
    ldconfig
  )

  # `make install` always drops the compiled pyscca.so into the generic,
  # unversioned /usr/local/lib/python3/dist-packages — confirmed live
  # against this exact release (--with-pythondir has no effect on this
  # particular path; it's hardcoded in pyscca/Makefile, not threaded
  # through from the top-level configure option). Modern Debian/Ubuntu
  # python3 only searches a VERSIONED .../python3.NN/dist-packages, which
  # that generic path isn't on, so `import pyscca` fails with the module
  # sitting right there unless it's also placed into the directory this
  # specific python3 build actually resolves.
  python_site_packages="$(python3 -c "import sysconfig; print(sysconfig.get_path('platlib'))")"
  mkdir -p "$python_site_packages"
  cp /usr/local/lib/python3/dist-packages/pyscca.so "$python_site_packages/"

  rm -rf "$libscca_build_dir"
  trap - EXIT

  python3 -c "import pyscca; print('pyscca', pyscca.get_version())"
fi

# Same rationale as libscca above: Debian/Ubuntu ship no python3-libfsntfs
# package at all (as of writing), so there's no "too old" case to detect —
# just install if missing.
LIBFSNTFS_VERSION="20260827"
LIBFSNTFS_URL="https://github.com/libyal/libfsntfs/releases/download/${LIBFSNTFS_VERSION}/libfsntfs-experimental-${LIBFSNTFS_VERSION}.tar.gz"
LIBFSNTFS_SHA256="72f46ed374c5e61bf24bf840eed10869f593a0d1d9123d07212d0eb336a6eed7"

if ! python3 -c "import pyfsntfs" >/dev/null 2>&1; then
  echo "==> Building libfsntfs ${LIBFSNTFS_VERSION} from source (Windows Artifact Analysis \$MFT dependency)"
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config python3-dev python3-setuptools

  libfsntfs_build_dir="$(mktemp -d)"
  trap 'rm -rf "$libfsntfs_build_dir"' EXIT
  curl -fsSL -o "${libfsntfs_build_dir}/libfsntfs.tar.gz" "$LIBFSNTFS_URL"
  echo "${LIBFSNTFS_SHA256}  ${libfsntfs_build_dir}/libfsntfs.tar.gz" | sha256sum -c -
  tar -xzf "${libfsntfs_build_dir}/libfsntfs.tar.gz" -C "$libfsntfs_build_dir"
  (
    cd "${libfsntfs_build_dir}/libfsntfs-${LIBFSNTFS_VERSION}"
    ./configure --enable-python
    make -j"$(nproc)"
    make install
    ldconfig
  )

  # Same "make install drops the .so in an unversioned dist-packages path"
  # gotcha as libscca above.
  python_site_packages="$(python3 -c "import sysconfig; print(sysconfig.get_path('platlib'))")"
  mkdir -p "$python_site_packages"
  cp /usr/local/lib/python3/dist-packages/pyfsntfs.so "$python_site_packages/"

  rm -rf "$libfsntfs_build_dir"
  trap - EXIT

  python3 -c "import pyfsntfs; print('pyfsntfs', pyfsntfs.get_version())"
fi

LIBESEDB_VERSION="20260704"
LIBESEDB_URL="https://github.com/libyal/libesedb/releases/download/${LIBESEDB_VERSION}/libesedb-experimental-${LIBESEDB_VERSION}.tar.gz"
LIBESEDB_SHA256="78f5e4cd11b551e673db270a9d40abf3c8ec8523b91939a9251ca80ee5a83bd1"

if ! python3 -c "import pyesedb" >/dev/null 2>&1; then
  echo "==> Building libesedb ${LIBESEDB_VERSION} from source (Windows Artifact Analysis SRUM dependency)"
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config python3-dev python3-setuptools

  libesedb_build_dir="$(mktemp -d)"
  trap 'rm -rf "$libesedb_build_dir"' EXIT
  curl -fsSL -o "${libesedb_build_dir}/libesedb.tar.gz" "$LIBESEDB_URL"
  echo "${LIBESEDB_SHA256}  ${libesedb_build_dir}/libesedb.tar.gz" | sha256sum -c -
  tar -xzf "${libesedb_build_dir}/libesedb.tar.gz" -C "$libesedb_build_dir"
  (
    cd "${libesedb_build_dir}/libesedb-${LIBESEDB_VERSION}"
    ./configure --enable-python
    make -j"$(nproc)"
    make install
    ldconfig
  )

  python_site_packages="$(python3 -c "import sysconfig; print(sysconfig.get_path('platlib'))")"
  mkdir -p "$python_site_packages"
  cp /usr/local/lib/python3/dist-packages/pyesedb.so "$python_site_packages/"

  rm -rf "$libesedb_build_dir"
  trap - EXIT

  python3 -c "import pyesedb; print('pyesedb', pyesedb.get_version())"
fi

if [[ ! -x "${APP_DIR}/.venvs/winartifacts/bin/python3" ]]; then
  echo "==> Creating Windows Artifact Analysis venv"
  # python3-venv isn't pulled in by the libscca branch above when libscca
  # is already new enough to skip it — needed unconditionally here for
  # `python3 -m venv` itself. No-op (apt skips it instantly) if already present.
  if ! dpkg -s python3-venv >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv
  fi
  mkdir -p "${APP_DIR}/.venvs"
  chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/.venvs"
  runuser -u "$SERVICE_USER" -- bash -lc "python3 -m venv '${APP_DIR}/.venvs/winartifacts'"
fi

# Always re-run pip install against the current package list (not just on
# first creation) — pip itself is idempotent for already-satisfied
# packages, and this is what actually backfills a NEW dependency (like
# bits_parser/minidump, added after this venv already existed on an
# already-deployed instance) onto every instance that updates in place,
# not just fresh installs. Matches this script's own stated idempotency
# goal — see the header comment on why provision.sh alone isn't enough.
echo "==> Installing regipy, LnkParse3, olefile, bits_parser, minidump (Windows Artifact Analysis pure-Python dependencies)"
runuser -u "$SERVICE_USER" -- bash -lc "
  '${APP_DIR}/.venvs/winartifacts/bin/pip' install --upgrade pip &&
  '${APP_DIR}/.venvs/winartifacts/bin/pip' install 'regipy[full]' LnkParse3 olefile bits_parser minidump
" || echo "WARNING: one or more pure-Python Windows Artifact Analysis dependencies failed to install — affected artifact types will be unavailable until installed manually"
