package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/bogdanfinn/utls/dicttls"
	"github.com/dreadl0ck/tlsx"
	"github.com/senonide/fingerproxy/pkg/debug"
	"github.com/senonide/fingerproxy/pkg/ja3"
	"github.com/senonide/fingerproxy/pkg/ja4"
	"github.com/senonide/fingerproxy/pkg/metadata"
	"github.com/senonide/fingerproxy/pkg/proxyserver"
)

var (
	flagListenAddr, flagCertFilename, flagKeyFilename *string

	flagBenchmarkControlGroup, flagVerbose, flagQuiet *bool

	tlsConf *tls.Config

	ctx, _ = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
)

func main() {
	parseFlags()

	setupTLSConfig()

	if *flagBenchmarkControlGroup {
		runAsControlGroup()
	} else {
		run()
	}
}

func parseFlags() {
	flagListenAddr = flag.String(
		"listen-addr",
		"localhost:8443",
		"Listening address",
	)
	flagCertFilename = flag.String(
		"cert-filename",
		"tls.crt",
		"TLS certificate filename",
	)
	flagKeyFilename = flag.String(
		"certkey-filename",
		"tls.key",
		"TLS certificate key file name",
	)
	flagBenchmarkControlGroup = flag.Bool(
		"benchmark-control-group",
		false,
		"Start a golang default TLS server as the control group for benchmarking",
	)
	flagVerbose = flag.Bool("verbose", false, "Print fingerprint detail in logs, conflict with -quiet")
	flagQuiet = flag.Bool("quiet", false, "Do not print fingerprints in logs, conflict with -verbose")
	flag.Parse()

	if *flagVerbose && *flagQuiet {
		log.Fatal("-verbose and -quiet cannot be specified at the same time")
	}
}

func setupTLSConfig() {
	tlsConf = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}

	if tlsCert, err := tls.LoadX509KeyPair(*flagCertFilename, *flagKeyFilename); err != nil {
		log.Fatal(err)
	} else {
		tlsConf.Certificates = []tls.Certificate{tlsCert}
	}
}

func runAsControlGroup() {
	// create golang default https server
	server := &http.Server{
		Addr:      *flagListenAddr,
		Handler:   http.HandlerFunc(echoServer),
		TLSConfig: tlsConf,
	}
	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	// listen and serve
	log.Printf("server (benchmark control group) listening on %s", *flagListenAddr)
	err := server.ListenAndServeTLS("", "")
	log.Fatal(err)
}

func run() {
	// create proxyserver
	server := proxyserver.NewServer(ctx, http.HandlerFunc(echoServer), tlsConf)

	// start debug server if build tag `debug` is specified
	debug.StartDebugServer()

	// listen and serve
	log.Printf("server listening on %s", *flagListenAddr)
	err := server.ListenAndServe(*flagListenAddr)
	log.Fatal(err)
}

func echoServer(w http.ResponseWriter, req *http.Request) {
	// create logger for this request, it outputs logs with client IP and port as prefix
	logger := log.New(os.Stdout, fmt.Sprintf("[client %s] ", req.RemoteAddr), log.LstdFlags|log.Lmsgprefix)

	// get metadata from request context
	data, ok := metadata.FromContext(req.Context())
	if !ok {
		logger.Printf("failed to get context")
		http.Error(w, "failed to get context", http.StatusInternalServerError)
		return
	}

	// prepare response
	response := &echoResponse{
		log: logger,
		Detail: &detailResponse{
			Metadata:  data,
			UserAgent: req.UserAgent(),
		},
	}

	// calculate and add fingerprints to the response
	if err := response.fingerprintJA3(); err != nil {
		logger.Printf(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := response.fingerprintJA4(); err != nil {
		logger.Printf(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response.fingerrpintHTTP2()

	// print detail if -verbose is specified in CLI
	if *flagVerbose {
		detail, _ := json.Marshal(response.Detail)
		logger.Printf("detail: %s", detail)
	}

	// send HTTP response
	switch req.URL.Path {
	case "/json":
		w.Header().Set("Content-Type", "application/json")
		response.Detail = nil
		json.NewEncoder(w).Encode(response)

	case "/json/detail":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	default:
		fmt.Fprintf(w, "User-Agent: %s\n", response.Detail.UserAgent)
		fmt.Fprintf(w, "TLS ClientHello Record: %x\n", response.Detail.Metadata.ClientHelloRecord)
		fmt.Fprintf(w, "JA3 fingerprint: %s\n", response.JA3)
		fmt.Fprintf(w, "JA4 fingerprint: %s\n", response.JA4)
		fmt.Fprintf(w, "HTTP2 fingerprint: %s\n", response.HTTP2)
	}
}

// echoResponse is the HTTP response struct of this echo server
type echoResponse struct {
	Detail *detailResponse `json:"detail,omitempty"`
	JA3    string          `json:"ja3"`
	JA4    string          `json:"ja4"`
	HTTP2  string          `json:"http2"`

	log *log.Logger
}

type detailResponse struct {
	Metadata  *metadata.Metadata `json:"metadata"`
	UserAgent string             `json:"user_agent"`
	JA3       *ja3Detail         `json:"ja3"`
	JA3Raw    string             `json:"ja3_raw"`
	JA4       *ja4Detail         `json:"ja4"`
}

func (r *echoResponse) fingerprintJA3() error {
	fp := &tlsx.ClientHelloBasic{}
	rd := r.Detail
	err := fp.Unmarshal(rd.Metadata.ClientHelloRecord)
	if err != nil {
		return err
	}

	ja3Raw := ja3.Bare(fp)

	rd.JA3 = (*ja3Detail)(fp)
	rd.JA3Raw = string(ja3Raw)
	r.JA3 = ja3.BareToDigestHex(ja3Raw)

	r.logf("ja3: %s", r.JA3)
	return nil
}

func (r *echoResponse) fingerprintJA4() error {
	fp := &ja4.JA4Fingerprint{}

	err := fp.UnmarshalBytes(r.Detail.Metadata.ClientHelloRecord, 't')
	if err != nil {
		return err
	}

	r.Detail.JA4 = (*ja4Detail)(fp)
	r.JA4 = fp.String()

	r.logf("ja4: %s", r.JA4)
	return nil
}

func (r *echoResponse) fingerrpintHTTP2() {
	protocol := r.Detail.Metadata.ConnectionState.NegotiatedProtocol
	if protocol == "h2" {
		r.HTTP2 = r.Detail.Metadata.HTTP2Frames.String()
		r.logf("http2: %s", r.HTTP2)
	} else if *flagVerbose {
		r.logf("protocol is %s, skipping HTTP2 fingerprinting", protocol)
	}
}

func (r *echoResponse) logf(format string, args ...any) {
	if !*flagQuiet {
		r.log.Printf(format, args...)
	}
}

type ja3Detail tlsx.ClientHelloBasic

type ja4Detail ja4.JA4Fingerprint

func (j *ja3Detail) MarshalJSON() ([]byte, error) {
	data := struct {
		ja3Detail
		ReadableCipherSuites    []string
		ReadableAllExtensions   []string
		ReadableSupportedGroups []string
	}{
		ja3Detail:               *j,
		ReadableCipherSuites:    make([]string, len(j.CipherSuites)),
		ReadableAllExtensions:   make([]string, len(j.AllExtensions)),
		ReadableSupportedGroups: make([]string, len(j.SupportedGroups)),
	}

	for i, v := range j.CipherSuites {
		u := uint16(v)
		if name, ok := dicttls.DictCipherSuiteValueIndexed[u]; ok {
			data.ReadableCipherSuites[i] = fmt.Sprintf("%s (0x%x)", name, u)
		} else {
			data.ReadableCipherSuites[i] = fmt.Sprintf("UNKNOWN (0x%x)", u)
		}
	}

	for i, v := range j.AllExtensions {
		if name, ok := dicttls.DictExtTypeValueIndexed[v]; ok {
			data.ReadableAllExtensions[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableAllExtensions[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}

	for i, v := range j.SupportedGroups {
		if name, ok := dicttls.DictSupportedGroupsValueIndexed[v]; ok {
			data.ReadableSupportedGroups[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableSupportedGroups[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}

	return json.Marshal(data)
}

func (j *ja4Detail) MarshalJSON() ([]byte, error) {
	data := struct {
		ja4Detail
		ReadableCipherSuites        []string
		ReadableExtensions          []string
		ReadableSignatureAlgorithms []string
	}{
		ja4Detail:                   *j,
		ReadableCipherSuites:        make([]string, len(j.CipherSuites)),
		ReadableExtensions:          make([]string, len(j.Extensions)),
		ReadableSignatureAlgorithms: make([]string, len(j.SignatureAlgorithms)),
	}

	for i, v := range j.CipherSuites {
		if name, ok := dicttls.DictCipherSuiteValueIndexed[v]; ok {
			data.ReadableCipherSuites[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableCipherSuites[i] = fmt.Sprintf("UNKNOWN (0x%x)", v)
		}
	}

	for i, v := range j.Extensions {
		if name, ok := dicttls.DictExtTypeValueIndexed[v]; ok {
			data.ReadableExtensions[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableExtensions[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}

	for i, v := range j.SignatureAlgorithms {
		if name, ok := dicttls.DictSignatureAlgorithmValueIndexed[uint8(v)]; ok {
			data.ReadableSignatureAlgorithms[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			data.ReadableSignatureAlgorithms[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}

	return json.Marshal(data)
}
