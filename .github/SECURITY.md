# Security policy

## Reporting a vulnerability

Please report security problems privately, through GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/RusticStack/hydra-engine/security/advisories/new)**

Do not open a public issue, pull request or discussion for a vulnerability. Only the maintainers
can see a private advisory, and we disclose it together with you once a fix is out.

Please include:

- what is affected: the commit or build, the OS and the JDK;
- a description, with the files and lines involved if you know them;
- steps or a small proof of concept that reproduces it;
- the impact: who can do what to whom;
- a suggested fix, if you have one.

We aim to acknowledge a report within a week and to agree on a disclosure date with you.

## Scope

In scope: everything this repository adds to Ghidra, above all the HeadlessSession module
(`Ghidra/Features/HeadlessSession`): its daemon, the loopback socket and its token check, the
endpoint and state files, the launcher `ghidra_session.py`, and the build files in
`gradle/hydra/`.

Things that work as designed (see the module README, "Security"):

- Anyone who can read your state directory can read the endpoint token and drive the daemon,
  with your rights.
- `script` runs Java (or Python) with the daemon's rights. Containment protects other clients'
  view of a program, not the machine. It is not a sandbox.
- A program you import or analyse is parsed by Ghidra's loaders and analysers. Analyse untrusted
  binaries the way you would with Ghidra itself: in an environment you are prepared to lose.

## Vulnerabilities in Ghidra itself

Most of the code here is upstream Ghidra. If the problem is in Ghidra (it also happens with a
Ghidra build from the [upstream repository](https://github.com/NationalSecurityAgency/ghidra)),
please report it to the Ghidra project as its
[security policy](https://github.com/NationalSecurityAgency/ghidra/security/policy) describes, and
let us know privately so that we can pick up the fix. Ghidra's own security policy is in
[`SECURITY.md`](../SECURITY.md) at the repository root.
