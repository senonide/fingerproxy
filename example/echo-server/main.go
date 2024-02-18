package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/wi1dcard/fingerproxy/pkg/fingerprint"
	"github.com/wi1dcard/fingerproxy/pkg/metadata"
	"github.com/wi1dcard/fingerproxy/pkg/proxyserver"
)

func main() {
	flagListenAddr := flag.String(
		"listen-addr",
		"localhost:8443",
		"Listening address",
	)
	flagCertFilename := flag.String(
		"cert-filename",
		"tls.crt",
		"TLS certificate filename",
	)
	flagKeyFilename := flag.String(
		"certkey-filename",
		"tls.key",
		"TLS certificate key file name",
	)
	flagVerboseLogs := flag.Bool("verbose", false, "Enable verbose logs")
	flag.Parse()

	// load TLS certs
	tlsConf := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	if tlsCert, err := tls.LoadX509KeyPair(*flagCertFilename, *flagKeyFilename); err != nil {
		log.Fatal(err)
	} else {
		tlsConf.Certificates = []tls.Certificate{tlsCert}
	}

	// enable verbose logs in fingerprint algorithms
	fingerprint.VerboseLogs = *flagVerboseLogs

	// shutdown on interrupt signal (ctrl + c)
	ctx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	// create proxyserver
	server := proxyserver.NewServer(ctx, http.HandlerFunc(echoServer), tlsConf)
	server.VerboseLogs = *flagVerboseLogs

	// listen and serve
	log.Printf("server listening on %s", *flagListenAddr)
	err := server.ListenAndServe(*flagListenAddr)
	log.Fatal(err)
}

func echoServer(w http.ResponseWriter, req *http.Request) {
	data, ok := metadata.FromContext(req.Context())
	if !ok {
		http.Error(w, "failed to get context", http.StatusInternalServerError)
	}

	ja3, err := fingerprint.JA3Fingerprint(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	ja4, err := fingerprint.JA4Fingerprint(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http2, err := fingerprint.HTTP2Fingerprint(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	fmt.Fprintf(w, "JA3 fingerprint: %s\n", ja3)
	fmt.Fprintf(w, "JA4 fingerprint: %s\n", ja4)
	fmt.Fprintf(w, "HTTP2 fingerprint: %s\n", http2)
}