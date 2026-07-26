# Security Policy

This gateway handles auth tokens, Sign in with Apple/Google identities, and
proxies your camera feeds — please report vulnerabilities privately rather
than in a public issue.

## Reporting

Email **support@tarazel.com** with a description and, if possible, steps to
reproduce. We'll acknowledge within a few days.

## Scope

In scope: this repo (auth, JWT/refresh handling, per-camera access control,
the Frigate/go2rtc proxying, the relay client). Out of scope: vulnerabilities
in Frigate itself, or in a self-hoster's own reverse proxy/tunnel setup —
report those upstream.
