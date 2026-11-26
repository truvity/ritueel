module ritueel.id/ritueel

go 1.27.0

require (
	connectrpc.com/connect v1.21.1 // pinned exactly: the generated client of the key port is built on it (record 0012, rule 1)
	filippo.io/age v1.3.2 // pinned exactly: an upgrade is a reviewed change with its key file tests (record 0002, rules 22 and 28)
	github.com/ProtonMail/go-crypto v1.5.2 // pinned exactly: an upgrade is a reviewed change with its signer test (record 0010, rule 20)
	github.com/truvity/atoom/common v0.10.0 // pinned exactly: the call context of the key port client, in process (record 0012, rule 1; its contract is v1alpha1)
	github.com/truvity/atoom/key v0.10.0 // pinned exactly: the key port, its purposes and its Signer (record 0012, rule 1; its contract is v1alpha1)
	github.com/truvity/atoom/key/software v0.10.0 // pinned exactly: the software driver for the keys of a test root (record 0012, rule 2)
	github.com/truvity/atoom/socket v0.10.0 // pinned exactly: the in-process link of a driver, with no socket and no port (record 0012, rule 1)
	github.com/urfave/cli/v3 v3.14.0
	go.yaml.in/yaml/v3 v3.0.6
	golang.org/x/sys v0.50.0
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
