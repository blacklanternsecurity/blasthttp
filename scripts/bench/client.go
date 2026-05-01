// HTTP benchmark client using Go's net/http stdlib.
// Worker-pool pattern: W goroutines pulling URLs from a channel, shared
// http.Client with connection pool sized to W so each worker can hold its
// own idle connection between requests.
//
// Usage: client <urls-file> <workers>
// Output: one JSON line per completed request to stdout:
//   {"url":"...","status":200}  or  {"url":"...","error":"..."}
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type result struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <urls-file> <workers>\n", os.Args[0])
		os.Exit(2)
	}
	urlsPath := os.Args[1]
	workers, err := strconv.Atoi(os.Args[2])
	if err != nil || workers <= 0 {
		fmt.Fprintf(os.Stderr, "invalid workers: %v\n", os.Args[2])
		os.Exit(2)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	f, err := os.Open(urlsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open urls: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	transport := &http.Transport{
		MaxIdleConns:        workers,
		MaxIdleConnsPerHost: workers,
		MaxConnsPerHost:     workers,
		IdleConnTimeout:     60 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	urlCh := make(chan string, workers*2)
	resultCh := make(chan result, workers*2)

	var workerWg sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for url := range urlCh {
				resp, err := client.Get(url)
				if err != nil {
					resultCh <- result{URL: url, Error: err.Error()}
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				resultCh <- result{URL: url, Status: resp.StatusCode}
			}
		}()
	}

	// Writer goroutine: serializes JSON output to stdout.
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		out := bufio.NewWriter(os.Stdout)
		defer out.Flush()
		enc := json.NewEncoder(out)
		for r := range resultCh {
			enc.Encode(&r)
		}
	}()

	// Feed URLs.
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urlCh <- line
	}
	close(urlCh)

	workerWg.Wait()
	close(resultCh)
	writerWg.Wait()
}
