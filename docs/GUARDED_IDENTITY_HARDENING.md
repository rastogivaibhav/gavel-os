# Guarded identity hardening — first containment gate

The launcher previously set NoSetGroups=true, retaining the supervisor's supplementary groups across credential changes. Explicitly clear supplementary groups before executing any guarded workload. Existing privileged tests now require an empty supplementary group list in the guarded parent, descendant and crash survivor.

This is a narrow identity hardening change, not proof of cgroup escape prevention. Remaining gates: no_new_privs before untrusted exec, capability and namespace restrictions, trusted cgroup ownership/delegation validation, hostile migration tests, inherited descriptors and alternate socket paths. No claim of root containment. CI and independent review pending.

## Irreversible exec privilege gate

Guarded launch uses fixed root-owned /usr/bin/setpriv with no_new_privs and cleared inheritable/ambient capabilities before executing the requested program. Existing credential drop clears supplementary groups; privileged tests assert NoNewPrivs and zero inheritable, permitted, effective and ambient capability sets in parent, descendants and crash survivor. Dynamic-loader environment variables are removed. Host installation and parent directories are trusted; missing launcher fails closed. Bounding capabilities, user namespaces, hostile migration, and actual setuid/file-capability exec probes remain separate gates. No claim of full privilege containment until those tests pass.

## Adversarial acceptance probe

Isolated VM only: compare a root-owned setuid id fixture with and without the guard; require the positive control to elevate and guarded execution to retain UID 65534. Require setuid(0) to return EPERM and attempted migration into a root-owned sibling cgroup to return EACCES/EPERM with unchanged membership. This does not establish protection against delegated writable cgroups, privileged helpers, user namespaces or host root. CI pending.
