// Minimal HTTP benchmark target server.
// Serves a fixed ~1KB body as fast as possible on 127.0.0.1:8080.
package main

import (
	"flag"
	"log"
	"net/http"
	"runtime"
	"strings"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	runtime.GOMAXPROCS(runtime.NumCPU())

	body := []byte(strings.Repeat("A", 1024))

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "1024")
		w.Write(body)
	})

	log.Printf("bench server listening on http://%s/", *addr)
	srv := &http.Server{Addr: *addr, Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
