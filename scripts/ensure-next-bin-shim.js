#!/usr/bin/env node
// Some filesystems (e.g. a VMware vmhgfs-fuse shared folder) don't support
// symlinks, so `npm install` has to run with --no-bin-links there, which
// leaves node_modules/.bin empty. `npm run build`/`dev` then can't find the
// `next` binary via PATH and silently fall through to whatever other Next.js
// happens to be resolvable (wrong version, confusing failures).
//
// This recreates node_modules/.bin/next as a plain shell shim -- the same
// script npm itself writes for bin entries on filesystems without symlink
// support -- so `npm run build`/`dev` work without a manual workaround. A
// no-op if the shim or a real symlink already exists.

const fs   = require("fs");
const path = require("path");

const binDir  = path.join(__dirname, "..", "node_modules", ".bin");
const shimPath = path.join(binDir, "next");

if (fs.existsSync(shimPath)) process.exit(0);

const shim = `#!/bin/sh
basedir=$(dirname "$(echo "$0" | sed -e 's,\\\\,/,g')")

case \`uname\` in
    *CYGWIN*|*MINGW*|*MSYS*) basedir=\`cygpath -w "$basedir"\`;;
esac

if [ -x "$basedir/node" ]; then
  exec "$basedir/node"  "$basedir/../next/dist/bin/next" "$@"
else
  exec node  "$basedir/../next/dist/bin/next" "$@"
fi
`;

fs.mkdirSync(binDir, { recursive: true });
fs.writeFileSync(shimPath, shim, { mode: 0o755 });
console.log("Recreated missing node_modules/.bin/next shim");
