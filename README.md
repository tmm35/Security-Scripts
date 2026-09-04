# Security Sripts

A collection of scripts for blue team / defensive security work, checks you can run against your own environment to identify misconfigurations before someone else finds them.

I typically build these out in a private repository while I test them, once I feel they are complete enough, I'll move them here.
## Intended audience

Most of these are written for **blue teams / defenders** auditing their own environment, finding misconfigurations so you can fix them, not exploit them. Check each script's own header/section below for its specific intent; a few may be general-purpose and have nothing to do with security at all.

I try to ensure each script has a usage output and some comments describing what the general purpose is at the top, but I may accidentally leave that out. If I do, sorry about that (you can ask AI what it is doing).

## Use responsibly

Anything that touches Active Directory or a live network should only be run against systems you own or are explicitly authorized to assess.

## Index

| Script | Language | Purpose |
|---|---|---|
| `find-kerberoastable-users.*` | — | Enumerates accounts vulnerable to Kerberoasting (SPN set, weak/old passwords, privileged group membership) |
| `find-write-delegation.*` | — | Enumerates dangerous ACL/delegation misconfigs (`GenericWrite`, `WriteDACL`, `WriteOwner`, unconstrained/constrained delegation) |

