package main

import (
	"fmt"

	"github.com/dreadl0ck/tlsx"
	"github.com/senonide/fingerproxy/internal/cli"
	"github.com/senonide/fingerproxy/pkg/fingerprint"
	"github.com/senonide/fingerproxy/pkg/ja3"
	"github.com/senonide/fingerproxy/pkg/metadata"
	"github.com/senonide/fingerproxy/pkg/reverseproxy"
)

func main() {
	cli.GetHeaderInjectors = func() []reverseproxy.HeaderInjector {
		i := cli.DefaultHeaderInjectors()
		i = append(i, fingerprint.NewFingerprintHeaderInjector(
			"X-JA3-Raw-Fingerprint",
			fpJA3Raw,
		))
		return i
	}
	cli.Run()
}

func fpJA3Raw(data *metadata.Metadata) (string, error) {
	hellobasic := &tlsx.ClientHelloBasic{}
	if err := hellobasic.Unmarshal(data.ClientHelloRecord); err != nil {
		return "", fmt.Errorf("ja3: %w", err)
	}

	fp := string(ja3.Bare(hellobasic))

	return fp, nil
}
