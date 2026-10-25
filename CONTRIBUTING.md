# Contributing

Keep learner-visible protocol claims tied to executable results and primary specifications. A change to key derivation, byte encoding, state order or a displayed verdict needs an independent check plus a negative test that would fail if the behavior regressed.

Before opening a pull request, run `npm ci` and `npm run ci`, then the browser/accessibility and mutation gates documented in the README. Do not weaken coverage or mutation thresholds to make a change pass. Preserve keyboard access, narrow-screen reflow and the explicit bounded-profile language.
