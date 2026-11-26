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
| [`copy-fail`](shields/CVE-2026-31431-copy-fail-af-alg/) | Copy Fail (CVE-2026-31431) | `lsm/socket_bind` | 1.0.0 | 6.1–6.18 | published |
| [`cve-2026-98432`](shields/CVE-2026-98432-tcp-ip-options/) | IPv4 TCP IP options (CVE-2026-98432) | `cgroup_skb/ingress` | 1.0.0 | 6.1–7.2 | published |
| [`cve-2026-99567`](shields/CVE-2026-99567-assoc-array/) | assoc_array keyring (CVE-2026-99567) | `lsm/key_permission`, `lsm/key_alloc`, `lsm/task_free` + 8 helpers | 1.0.0 | 6.1–7.3 | published |
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
