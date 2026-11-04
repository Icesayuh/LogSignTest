"use client";

import { useEffect, useState } from "react";

const TICK_MS = 1000;

const timeFormat: Intl.DateTimeFormatOptions = { hour: "numeric", minute: "2-digit" };
const dateFormat: Intl.DateTimeFormatOptions = { weekday: "long", month: "long", day: "numeric" };

// Rendered only after mount: the server's clock and timezone would never match the visitor's.
export function Clock() {
  const [now, setNow] = useState<Date | null>(null);

  useEffect(() => {
    setNow(new Date());
    const timer = window.setInterval(() => setNow(new Date()), TICK_MS);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="clock" aria-hidden="true">
      {now && (
        <>
          <span className="clock-time">{now.toLocaleTimeString(undefined, timeFormat)}</span>
          <span className="clock-date">{now.toLocaleDateString(undefined, dateFormat)}</span>
        </>
      )}
    </div>
  );
}
