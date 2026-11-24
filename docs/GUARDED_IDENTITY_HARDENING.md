# Guarded identity hardening — first containment gate

The launcher previously set NoSetGroups=true, retaining the supervisor's supplementary groups across credential changes. Explicitly clear supplementary groups before executing any guarded workload. Existing privileged tests now require an empty supplementary group list in the guarded parent, descendant and crash survivor.

This is a narrow identity hardening change, not proof of cgroup escape prevention. Remaining gates: no_new_privs before untrusted exec, capability and namespace restrictions, trusted cgroup ownership/delegation validation, hostile migration tests, inherited descriptors and alternate socket paths. No claim of root containment. CI and independent review pending.
