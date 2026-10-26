/**
 * Handlers for an API path that moved. Updates extract each release over the
 * previous tree (files are never deleted), so an old route file would keep
 * running its old code unless the new release overwrites it — every moved
 * route ships one of these at its old path instead.
 */
import { NextResponse } from "next/server";

export function movedTo(newPath: string) {
  const gone = () =>
    NextResponse.json(
      { error: "moved", message: `This endpoint moved to ${newPath}.`, location: newPath },
      { status: 410 },
    );
  return { GET: gone, POST: gone, PUT: gone, PATCH: gone, DELETE: gone };
}
