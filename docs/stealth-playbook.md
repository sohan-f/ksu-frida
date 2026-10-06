# Stealth playbook: observing an injected app

This is guidance for *using* Frida against a target that hides it, not for
changing the module. The module's dormant state is quiet; every technique
below trades visibility in one place for visibility in another.

## Prefer Stalker over Interceptor for observation

`Interceptor.attach` rewrites function prologues in place, which any
memcmp-against-disk or prologue-signature check detects. `Stalker.follow`
instead recompiles basic blocks into instrumented copies elsewhere and
never modifies the original bytes, so code-comparison checks pass.

Costs, payable per followed thread:

- Performance: expect multiples, not percent. Keep followed threads off
  the critical path or the app will jank.
- Coverage: Stalker follows one thread at a time and skips excluded
  ranges. Use `Stalker.follow_me` from inside the thread of interest;
  `follow(thread_id)` on another thread goes through ptrace, which shows
  up as a non-zero `TracerPid`.
- Reliability: interceptors may silently not fire under Stalker (use call
  probes); self-modifying and JIT-compiled code interact with the trust
  threshold.
- Footprint: multi-megabyte code-cache slabs plus side-stack frames on
  thread stacks. Exclude aggressively and unfollow when done so the slabs
  are freed.

## Intercepting (not just observing) stays visible

Redirecting execution always leaves a trace somewhere: patched bytes,
fresh executable mappings, bridge frames on stacks, or handler latency.
Hardware breakpoints (`PERF_TYPE_BREAKPOINT`) avoid code modification for
a handful of targets but need custom agent code, contend for few slots,
and still pay timing. There is no undetectable active interception
against a thorough detector; keep active sessions short and targeted.

## Dormant checklist (module side, all verified)

- Verbose logs show `Hide verify clean` per library, never `LEAK`.
- Maps show no source paths, no memfd names, renamed anon segments only.
- Module and thread lists show no `frida`/`gadget`/`gum` keywords.
- With `scrub_elf_header` on, anonymous bases carry no ELF magic.
- Cold start matches the uninjected baseline within noise.
