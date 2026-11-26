# Contributing

Embargoed bugs never go into a public pull request: see [SECURITY.md](SECURITY.md).

## The bar

- Refuse only the exploit condition, never a whole feature. If it breaks
  legitimate use, it does not ship.
- The hook runs before the vulnerable code on every path, on every kernel
  line listed. You are responsible for the lines you list.
- No exploit code anywhere: no proof of concept, payload or anything that
  fetches one.
- One CO-RE BPF object per package, attachable by the Shirudo stock-kernel
  port (`lsm/`, `fentry/`, `fexit/`, `tp_btf/`, `fmod_ret/`, `kprobe/`,
  `kretprobe/`, `cgroup_skb/`, `netfilter`, `xdp/`).
- Signed options in `.rodata` (`config.list`): at least `mode=enforce|audit`
  and an exemption.

## A shield

`tools/new-shield CVE-YYYY-NNNNN <slug> --hook lsm/<hook>` scaffolds
`shields/<CVE>-<slug>/`; replace every TODO.

| File | |
|---|---|
| `shield.toml` | Metadata ([schema](schema/shield.schema.json)): CVEs, fixes, hooks, vendor fixed packages per distro (`[[affected.fixes]]`), the installer's `[relevance]` checks, `[[versions]]` with their kernel lines. |
| `Beefile` | Package recipe; `kernel_release_prefix` = the kernel lines. |
| `<slug>.bpf.c` | The program. |
| `config.list`, `gen_config_rodata.py` | Options and their `.rodata` generator. |
| `README.md` | Ships in the package. Sections: How it works, What breaks, Not covered, Kernels, Install, References. |

**Names.** The package is the bug's canonical name (`copy-fail`), else its
CVE id in lower case (`cve-2026-98432`). **Versions** are the shield's own
SemVer revision, `1.0.0` first, never a kernel version; a published version
is immutable (the README ships in it too). **Kernel lines** are
`uname -r` prefixes, matched at a `.`, `-` or the end (`6.1` matches
`6.1.0-44-cloud-amd64`, not `6.10.3`). **Withdrawing**: set
`withdrawn = "<reason>"` on the version or the shield.

## Checks

```
pip install -r tools/requirements.txt
tools/validate
tools/export-registry --write      # commit the result
docker build -t shield-ci-clang tools/ci
tools/build --unpinned --image shield-ci-clang --libbpf <shirudo>/vendor/libbpf --vmlinux <vmlinux.h>
```

CI runs the same. Maintainers review and test on vulnerable vendor kernels
of every listed line; merging publishes.

## License and sign-off

Everything is `GPL-2.0 OR BSD-2-Clause`; code files start with an SPDX line
(`// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause`), BPF programs
declare `"Dual BSD/GPL"`. Commits from forks carry a DCO sign-off
(`git commit -s`).
