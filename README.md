# Security Sripts

A collection of scripts for blue team / defensive security work, checks you can run against your own environment to identify misconfigurations before someone else finds them.
## Intended audience

Most of these are written for **blue teams / defenders** auditing their own environment — finding misconfigurations so you can fix them, not exploit them. Check each script's own header/section below for its specific intent; a few may be general-purpose and have nothing to do with security at all.

## ⚠️ Use responsibly

Anything that touches Active Directory or a live network should only be run against systems you own or are explicitly authorized to assess.

## Index

| Script | Language | Purpose |
|---|---|---|
| `find-kerberoastable-users.*` | — | Enumerates accounts vulnerable to Kerberoasting (SPN set, weak/old passwords, privileged group membership) |
| `find-write-delegation.*` | — | Enumerates dangerous ACL/delegation misconfigs (`GenericWrite`, `WriteDACL`, `WriteOwner`, unconstrained/constrained delegation) |

*(Add a row per script as it goes in. Fill in Language once you know it.)*

## Structure

Each script should be self-contained (or in its own subfolder if it needs supporting files), with:
- A header comment: what it does, required permissions, example usage
- Read-only/non-destructive behavior by default — no script should modify state without an explicit opt-in flag

## Requirements

Varies per script — see each script's header. AD-focused ones generally need a domain-authenticated account with read access; no special privileges required for enumeration.

## License

MIT (swap if you want something else)
