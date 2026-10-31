# Contributing

Keep changes small and include an offline test for protocol or integrity
changes. Use synthetic UIDs, passwords and packet fixtures. Use RFC 5737
documentation addresses when an address is needed in a test. Never submit
captures or recordings from an actual camera.

Run from the repository root:

```sh
gofmt -w *.go
go test ./...
go test -race ./...
go vet ./...
python3 scripts/check_privacy.py
git diff --check
```

The privacy script checks tracked working-tree files. Stage newly added files
before running it. Check staged changes manually as well. Synthetic fixtures,
the vendor's relay endpoints and its fixed wire-transform constant are expected
protocol data, not user credentials.

Preserve upstream attribution and explain the evidence for protocol changes.
Do not upload vendor binaries, firmware, decompiler exports or private runtime
data. Describe device/firmware compatibility without identifying the owner,
location, device UID, account or network.
