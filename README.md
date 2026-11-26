# shirudo-shields

Kernel CVE shields for [Shirudo](https://github.com/shirudo-dev/shirudo).
A shield is a small signed BPF program (an LSM or cgroup hook) that refuses
the one condition a kernel bug's exploit needs, on hosts that do not run
the fixed kernel yet. A shield that breaks legitimate use does not ship.
`main` is published to registry.conformal.co, signed with the certificate
in [`keys/conformal.der`](keys/conformal.der).

<!-- shields:table:begin -->
| Package | Bug | Hook | Version | Kernel lines | Status |
|---|---|---|---|---|---|
<!-- shields:table:end -->

```
sudo shirudo bpm install conformal/<package>@<version>
```

Each shield's README says what it refuses, what breaks, what it does not
cover and which kernel lines it fits.

Contributions are welcome: open a pull request with a new shield or a fix;
maintainers review and test it. See [CONTRIBUTING.md](CONTRIBUTING.md), and
[SECURITY.md](SECURITY.md) for embargoed bugs and bypasses.

License: `GPL-2.0 OR BSD-2-Clause` ([LICENSE](LICENSE)).
