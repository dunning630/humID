#!/usr/bin/env bash
# Builds the HumID holder-cell base image (docs/CELLS.md): humid-cell.vhdx, for Hyper-V
# Generation 2 with Secure Boot (Microsoft UEFI CA template).
#
#   tools/cells/build-image.sh OUT_DIR
#
# Debian 13 "genericcloud" (its cloud kernel has the Hyper-V drivers, and its shim is signed
# for Secure Boot), plus: Node 22 (official build, which carries OpenSSL 3.5 for the hybrid
# post-quantum key exchange), the vault service as one bundled file, the cell's boot script
# and units. No SSH, no cloud-init, root locked, no console login. Every download is checked
# against its publisher's checksum list. Needs: qemu-utils, libguestfs-tools, curl, node 22.
set -euo pipefail
out=${1:?usage: build-image.sh OUT_DIR}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"

DEBIAN=https://cloud.debian.org/images/cloud/trixie/latest
IMG=debian-13-genericcloud-amd64.qcow2
NODE_MAJOR=22

echo "== Debian base"
curl -fsSL "$DEBIAN/SHA512SUMS" -o "$work/SHA512SUMS"
curl -fsSL "$DEBIAN/$IMG" -o "$work/$IMG"
(cd "$work" && grep " $IMG\$" SHA512SUMS | sha512sum -c -)

echo "== Node $NODE_MAJOR"
NODE_VER=$(curl -fsSL https://nodejs.org/dist/index.json | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const v=JSON.parse(s).find(r=>r.version.startsWith("v'"$NODE_MAJOR"'."));process.stdout.write(v.version)})')
NODE_TGZ=node-$NODE_VER-linux-x64.tar.xz
curl -fsSL "https://nodejs.org/dist/$NODE_VER/SHASUMS256.txt" -o "$work/SHASUMS256.txt"
curl -fsSL "https://nodejs.org/dist/$NODE_VER/$NODE_TGZ" -o "$work/$NODE_TGZ"
(cd "$work" && grep " $NODE_TGZ\$" SHASUMS256.txt | sha256sum -c -)
mkdir -p "$work/opt"
tar -xJf "$work/$NODE_TGZ" -C "$work/opt"
mv "$work/opt/node-$NODE_VER-linux-x64" "$work/opt/node"
rm -rf "$work/opt/node/include" "$work/opt/node/share" "$work/opt/node/lib/node_modules/npm" "$work/opt/node/lib/node_modules/corepack" "$work/opt/node/bin/npm" "$work/opt/node/bin/npx" "$work/opt/node/bin/corepack"
"$work/opt/node/bin/node" -e 'require("tls").createSecureContext({ ecdhCurve: "X25519MLKEM768" })' \
  || { echo "this Node can't do X25519MLKEM768" >&2; exit 1; }

echo "== vault bundle"
node "$repo/services/build-service.mjs" vault
cp "$repo/services/vault/dist/server.mjs" "$work/vault.mjs"

echo "== customise"
export LIBGUESTFS_BACKEND=direct
virt-customize -a "$work/$IMG" \
  --install nftables,e2fsprogs \
  --run-command 'apt-get purge -y --auto-remove openssh-server cloud-init cloud-guest-utils || true' \
  --run-command 'useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin humid' \
  --copy-in "$work/opt/node:/opt" \
  --mkdir /opt/humid \
  --upload "$work/vault.mjs:/opt/humid/vault.mjs" \
  --upload "$here/guest/humid-cell-init:/usr/local/sbin/humid-cell-init" \
  --upload "$here/guest/humid-cell-init.service:/etc/systemd/system/humid-cell-init.service" \
  --upload "$here/guest/humid-cell.service:/etc/systemd/system/humid-cell.service" \
  --run-command 'chmod 755 /usr/local/sbin/humid-cell-init && chmod -R a+rX /opt/node /opt/humid' \
  --run-command 'rm -f /etc/systemd/network/*.network /etc/network/interfaces.d/* || true' \
  --run-command 'systemctl enable systemd-networkd humid-cell-init humid-cell' \
  --run-command 'systemctl disable nftables || true' \
  --run-command 'systemctl mask getty@tty1.service serial-getty@ttyS0.service console-getty.service' \
  --run-command 'passwd -l root' \
  --run-command 'apt-get clean && rm -rf /var/lib/apt/lists/*' \
  --truncate /etc/machine-id

echo "== VHDX"
qemu-img convert -f qcow2 -O vhdx -o subformat=dynamic "$work/$IMG" "$out/humid-cell.vhdx"
(cd "$out" && sha256sum humid-cell.vhdx | tee humid-cell.vhdx.sha256)
echo "node $NODE_VER, $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/humid-cell.txt"
