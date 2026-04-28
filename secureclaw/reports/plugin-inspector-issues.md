# OpenClaw Plugin Issue Findings

Generated: deterministic
Status: PASS

## Triage Summary

| Metric               | Value |
| -------------------- | ----- |
| Issue findings       | 3     |
| P0                   | 0     |
| P1                   | 1     |
| Live issues          | 0     |
| Live P0 issues       | 0     |
| Compat gaps          | 0     |
| Deprecation warnings | 0     |
| Inspector gaps       | 3     |
| Upstream metadata    | 0     |
| Contract probes      | 3     |

## Triage Overview

| Class               | Count | P0 | Meaning                                                                                                         |
| ------------------- | ----- | -- | --------------------------------------------------------------------------------------------------------------- |
| live-issue          | 0     | 0  | Potential runtime breakage in the target OpenClaw/plugin pair. P0 only when it is not a deprecated compat seam. |
| compat-gap          | 0     | -  | Compatibility behavior is needed but missing from the target OpenClaw compat registry.                          |
| deprecation-warning | 0     | -  | Plugin uses a supported but deprecated compatibility seam; keep it wired while migration exists.                |
| inspector-gap       | 3     | -  | Plugin Inspector needs stronger capture/probe evidence before making contract judgments.                        |
| upstream-metadata   | 0     | -  | Plugin package or manifest metadata should improve upstream; not a target OpenClaw live break by itself.        |
| fixture-regression  | 0     | -  | Fixture no longer exposes an expected seam; investigate fixture pin or scanner drift.                           |

## P0 Live Issues

_none_

## Live Issues

_none_

## Compat Gaps

_none_

## Deprecation Warnings

_none_

## Inspector Proof Gaps

- P1 **secureclaw** `inspector-gap` `inspector-follow-up`
  - **registration-capture-gap**: secureclaw: runtime registrations need capture before contract judgment
  - state: open · compat:none
  - evidence:
    - registerService @ src/index.ts:295
    - registerService @ src/index.ts:301
    - registerService @ src/index.ts:307

- P2 **secureclaw** `inspector-gap` `inspector-follow-up`
  - **package-build-artifact-entrypoint**: secureclaw: cold import requires package build output
  - state: open · compat:none
  - evidence:
    - extension:./dist/index.js -> dist/index.js

- P2 **secureclaw** `inspector-gap` `inspector-follow-up`
  - **package-dependency-install-required**: secureclaw: cold import requires isolated dependency installation
  - state: open · compat:none
  - evidence:
    - chokidar @ package.json
    - node-forge @ package.json
    - openclaw @ package.json

## Upstream Metadata Issues

_none_

## Issues

- P1 **secureclaw** `inspector-gap` `inspector-follow-up`
  - **registration-capture-gap**: secureclaw: runtime registrations need capture before contract judgment
  - state: open · compat:none
  - evidence:
    - registerService @ src/index.ts:295
    - registerService @ src/index.ts:301
    - registerService @ src/index.ts:307

- P2 **secureclaw** `inspector-gap` `inspector-follow-up`
  - **package-build-artifact-entrypoint**: secureclaw: cold import requires package build output
  - state: open · compat:none
  - evidence:
    - extension:./dist/index.js -> dist/index.js

- P2 **secureclaw** `inspector-gap` `inspector-follow-up`
  - **package-dependency-install-required**: secureclaw: cold import requires isolated dependency installation
  - state: open · compat:none
  - evidence:
    - chokidar @ package.json
    - node-forge @ package.json
    - openclaw @ package.json

## Contract Probe Backlog

- P1 **secureclaw** `inspector-capture-api`
  - contract: External inspector capture records service, route, gateway, command, and interactive registrations.
  - id: `api.capture.runtime-registrars:secureclaw`
  - evidence:
    - registerService @ src/index.ts:295
    - registerService @ src/index.ts:301
    - registerService @ src/index.ts:307

- P2 **secureclaw** `package-loader`
  - contract: Inspector can build or resolve source aliases before cold importing package entrypoints.
  - id: `package.entrypoint.build-before-cold-import:secureclaw`
  - evidence:
    - extension:./dist/index.js -> dist/index.js

- P2 **secureclaw** `package-loader`
  - contract: Inspector installs package dependencies in an isolated workspace before cold import.
  - id: `package.entrypoint.isolated-dependency-install:secureclaw`
  - evidence:
    - chokidar @ package.json
    - node-forge @ package.json
    - openclaw @ package.json
