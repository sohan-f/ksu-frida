# WebUI desktop preview

See and click the WebUI on your computer. No device, no flashing.

```shell
cd template/ksu_module/webroot
npm run preview
# open http://localhost:8090/
```

The `preview` script rebuilds `main.js`, then serves `webroot/` with
`preview/mock.js` injected before `main.js`. The mock fakes the KernelSU
bridge (`ksu.exec`, package lists, toasts) with in-memory fixtures: two
sample targets, one running, port 27042 listening, gadget `17.22.1`
installed with `17.33.0` update available. Saves persist in memory until
you refresh the page.

Download simulation always succeeds; verbose toggle, search, labels,
the library browser, and the update-check flow all run against the fixtures.

Files here are dev-only: packaging copies `template/` plus the root
config example, so nothing under `preview/` ships to a device. If a
marker constant changes in `src/util.ts` or `main.ts`, mirror it in
`mock.js` (each is noted with a sync comment).
