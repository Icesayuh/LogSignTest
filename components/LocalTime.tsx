"use client";

import { useEffect, useState } from "react";

const dateTimeFormat: Intl.DateTimeFormatOptions = { dateStyle: "medium", timeStyle: "short" };
const dateOnlyFormat: Intl.DateTimeFormatOptions = { dateStyle: "medium" };

// Formats in the visitor's own timezone, which the server can't know; the ISO value stands in until mount.
export function LocalTime({ iso, dateOnly = false }: { iso: string; dateOnly?: boolean }) {
  const [label, setLabel] = useState<string | null>(null);

  useEffect(() => {
    setLabel(new Date(iso).toLocaleString(undefined, dateOnly ? dateOnlyFormat : dateTimeFormat));
  }, [iso, dateOnly]);

  return <time dateTime={iso}>{label ?? iso.slice(0, 10)}</time>;
}
