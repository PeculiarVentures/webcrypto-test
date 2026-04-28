# Project Instructions

- Use Vitest for test execution and coverage.
- `WebcryptoTest` supports an optional runner adapter; prefer the adapter when globals are not available.
- Keep published artifacts under `build/` and include all build outputs in the package files list.
- Do not reintroduce `prepare` unless the release workflow explicitly needs install-time builds.
- Run `npm run build`, `npm test`, and `npm run lint` before publishing changes.
- Prefer minimal, release-focused changes and avoid unrelated refactors.
