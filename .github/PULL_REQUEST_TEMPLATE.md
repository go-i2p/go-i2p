## Summary

- Describe the behavior change in 1-3 bullets.

## Validation

- [ ] `go test ./...`
- [ ] `go vet ./...`

## Dependency and Release Discipline

- [ ] If `go.mod`/`go.sum` changed, I reviewed deltas for `go-noise`, `common`, and `crypto`.
- [ ] If tracked dependencies changed, I attached compatibility evidence for transport/tunnel/netdb paths.
- [ ] I updated `RELEASE_NOTES.md` or documented why release notes are not needed.
- [ ] Release notes map to validated behavior changes (tests and/or artifacts linked in PR description).