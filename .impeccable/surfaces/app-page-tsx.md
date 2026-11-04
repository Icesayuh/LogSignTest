---
version: 1
slug: "app-page-tsx"
primary_target: "app/page.tsx"
related_targets: ["app/account/page.tsx"]
---

# Sign-in / Register surface

Scope: `/` (sign in + register) and `/account` (signed-in state). Mode: Operate.
Audience/job: testers and future users signing in to LogSignTest; register, sign in, confirm signed in, sign out.
Constraints: provider-agnostic auth layer; no security claims; Vercel deploy.

## Direction contract

THESIS: the workstation logon screen. One solid color field owns the whole viewport; the name, two fields and one button, nothing else. Refuses the centered white card on a gray page.

OWN-WORLD: full-bleed deep blue field (#0b3d5c family), white fields with square-ish 4px corners, pale sky-blue accent reserved for the primary action and focus, light coral for errors. One sourced grotesk at two weights. No cards, no shadows on the form, no illustration.

STORY: the visitor sees LogSignTest, knows this is where they sign in, does it in one column, and lands on a welcome screen that says who they are.

FIRST VIEWPORT: LogSignTest set large at upper left; a 360px form column centered vertically; mode heading, fields, full-width primary button; a quiet text switch to Register beneath; live clock and date bottom-left like a lock screen.

FORM: Workstation Logon, candidate 1 of the safer re-roll (user-picked, steer "keep it simple"), seed key 3dd929e5. Signature interaction: switching Sign in / Register grows the extra fields into the column with a height reveal while the heading swaps.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
