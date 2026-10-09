"use client";
import { useEffect, useState } from "react";

/**
 * The API base URL to show in developer docs. Upgrades from a relative
 * "/api" to the current browser origin, then to the instance's configured
 * App Domain (Settings -> General) once fetched, if one is set — that's
 * the stable, intentional URL an admin wants documented, rather than
 * whatever address a given visitor happens to be browsing from.
 *
 * Deliberately starts at "/api" (not window.location.origin) even though
 * window IS available on the client by the time this first runs —
 * useState's initializer must match what the server rendered, or React
 * throws a hydration mismatch (window doesn't exist during SSR). Both
 * upgrades below happen inside useEffect, which only ever runs
 * client-side, after hydration.
 */
export function useApiBaseUrl(): string {
  const [baseUrl, setBaseUrl] = useState("/api");

  useEffect(() => {
    setBaseUrl(`${window.location.origin}/api`);

    let cancelled = false;
    fetch("/api/settings/system")
      .then(r => (r.ok ? r.json() : null))
      .then(d => {
        if (!cancelled && d?.appDomain) setBaseUrl(`${d.appDomain}/api`);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  return baseUrl;
}
