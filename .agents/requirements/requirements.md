# Requirements

<!-- reqtracker:v2 next=10 -->

> Tracked automatically from what the user stated or explicitly approved. Suggestions Claude made on its own are not recorded here.

- [x] `R1` The project's build tasks are defined in Taskfile.yml `+build` `2026-10-19 → met 2026-10-19: Migration committed as 347deea build - migrate from Makefile to Taskfile`
- [x] `R2` The project has no Makefile `+build` `2026-10-19 → met 2026-10-19: Makefile deletion recorded in commit 347deea`
- [x] `R3` CI runs tests and OpenWrt package builds through Taskfile.yml; the container image is built by docker/build-push-action `+ci` `+build` `2026-10-19 → met 2026-10-19: reworded to the code and confirmed by the user before a commit`
- [x] `R4` The docs describe Taskfile.yml instead of the Makefile `+docs` `+build` `2026-10-19 → met 2026-10-19: Docs say task instead of make, done by commit 347deea`
- [x] `R5` Codacy does not flag Revive's package-comments rule for this repository `+ci` `2026-10-19 → met 2026-10-19: Revive's package-comments rule is now off for this repository, re-analysis went from 4 issues to 0`
- [ ] `R6` Codacy has Revive's package-comments rule disabled for all repositories `+ci` `2026-10-19`
- [x] `R7` CI attests build provenance and an SBOM with actions/attest for the image and ipk packages on v* tags `+ci` `+build` `2026-10-19 → met 2026-10-19: reworded to the code and confirmed by the user before a commit`
- [x] `R8` Codacy does not flag the id-token: write permission in the signing workflow as a hard-coded token `+ci` `2026-10-19 → met 2026-10-19: Finding marked as false positive in Codacy; fresh analysis of the PR reports 0 issues, down from 1`
- [x] `R9` Releases are cut by a manually run release workflow with a dropdown to pick whether Major, Minor or Patch is bumped `+ci` `+build` `2026-10-19 → met 2026-10-19: Release workflow changes committed as 1a268c6 on ci/attestations; manually run release workflow with patch, minor or major choice`
