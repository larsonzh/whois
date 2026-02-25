# whois release blurb (template)

A tiny, portable whois client purpose-built for BusyBox pipelines.

- Smart redirects: non-blocking connect, timeouts, light retries; follow referrals with loop guard (cap via -R, disable with -Q).
- Pipeline batch input: stable header/tail contract; stdin-driven (-B/implicit); ideal for large-scale grep/awk flows.
- Conditional output engine: title projection (-g) → regex filters (--grep/--grep-cs, line/block, optional continuation expansion) → single-line folded summary (--fold, sep/case options).

Highlights this release:
- Major improvement: adopts the IPv4/IPv6 lookup rules contract as the primary implementation/review baseline.
- CIDR rule-loop convergence: tightened authority decisions with a deterministic “marker + baseline + consistency” flow.
- LACNIC→ARIN refinement: non-IP-literal queries continue non-authoritative hopping without pre-marking ARIN visited.
- Governance progress: `--no-cidr-erx-recheck` is now deprecated (kept in this release for compatibility, planned removal next major).
- Validation baseline refreshed: Strict (two rounds) + CIDR Contract Bundle + Redirect Matrix 10x6 all PASS in the current gate window.

Links: Usage CN/EN, README, Releases.
