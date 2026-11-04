# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Next.js (App Router), deployed to Vercel; run locally first with `npm run dev`.

## Users

People signing in to or registering for LogSignTest. The exact audience is not yet decided; the first use is testing sign-in through a third-party identity console.

## Product Purpose

A working sign-in and registration page for LogSignTest. It exists so MFA and Active Directory integration can be tested through a third-party identity console. Success: a person can register, sign in, see they are signed in, and sign out.

## Capabilities and Constraints

- Sign in and register flows with validation and clear error states.
- MFA and AD are handled by a third-party console later; this page does not implement them.
- The identity provider is not decided yet (Entra ID, Okta, Auth0 all possible). The auth layer must be swappable so the provider can replace the built-in demo backend without redesigning the page.
- Must run on Vercel (serverless: no persistent local disk).

## Brand Commitments

Name: LogSignTest (as given by the user). No logo, voice, or other brand assets exist yet.

## Evidence on Hand

None. Do not invent customers, security claims, certifications, or compliance badges.

## Product Principles

- The form works first: every state (empty, invalid, submitting, error, success) is real.
- Nothing on the page claims security the provider has not delivered yet.
- The provider swap must not touch the page's design.
