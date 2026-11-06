This directory contains private acceptance helpers, not a shipping server or
client. The server process delegates every normal request to the real
`teamsync.NewHandler`; separate client processes call the real owner/device
client APIs with independent keys and durable anchor files. A capture wrapper
records complete application bodies and can replay an old response or discard
a response before/after the actual commit.

From the repository root on Linux:

```sh
python3 scripts/team_sync_acceptance.py --go /path/to/go
```

For an independently fixed helper build:

```sh
GOTOOLCHAIN=go1.27.3 go build -o /private/path/team-sync-fixture ./scripts/team_sync_fixture
python3 scripts/team_sync_acceptance.py --fixture-bin /private/path/team-sync-fixture
```

The runner prints booleans and classifications. It retains a unique 0700
directory beneath `/tmp/locklark-validation` (or `--artifacts`) containing 0600
synthetic keys, item canaries, exact ciphertext publications, full stdout/stderr,
request/response bodies and the final `result.json`. Those private files are
intentional test artifacts. No private fixture is added to the repository.

The plaintext oracle independently verifies current proposal/receipt/snapshot
signatures, unwraps the age envelope and decodes KDBX 4.1 directly. It does not
call the network client's plaintext APIs or `vault.OpenItems`. It compares exact
synthetic fields inside the private process and returns only booleans. The runner
scans complete process output and all captured application bodies for every
synthetic username, password and note, including base64/hex encodings.

The fixture is not evidence for the production command's hidden terminal input,
Windows service operation, mobile UI, or system credential hardware. Those need
their own platform acceptance.
