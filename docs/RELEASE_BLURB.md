# whois release blurb (template)

A tiny, portable whois client purpose-built for BusyBox pipelines.

- Smart redirects: non-blocking connect, timeouts, light retries; follow referrals with loop guard (cap via -R, disable with -Q).
- Pipeline batch input: stable header/tail contract; stdin-driven (-B/implicit); ideal for large-scale grep/awk flows.
- Conditional output engine: title projection (-g) → regex filters (--grep/--grep-cs, line/block, optional continuation expansion) → single-line folded summary (--fold, sep/case options).

Highlights this release:
- ...

Links: Usage CN/EN, README, Releases.
