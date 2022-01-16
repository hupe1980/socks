package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/hupe1980/socks"
)

func StartHTTPServer(wg *sync.WaitGroup) {
	log.Println("Starting HTTP server")

	go func() {
		http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			fmt.Fprint(rw, "Hello World")
		})

		if err := http.ListenAndServe("localhost:8080", nil); err != nil {
			panic(err)
		}
	}()

	wg.Done()
}

func StartSocksServer(wg *sync.WaitGroup) {
	log.Println("Starting socks server")

	go func() {
		log.Fatal(socks.ListenAndServe(":1080"))
	}()

	wg.Done()
}

func main() {
	wg := &sync.WaitGroup{}
	wg.Add(2)

	StartHTTPServer(wg)
	StartSocksServer(wg)

	wg.Wait()

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := socks.NewSocks5Dialer("tcp", "localhost:1080")
				return d.DialContext(ctx, network, addr)
			},
		},
	}

	resp, err := client.Get("http://localhost:8080")
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	log.Printf("[%s] %s", resp.Status, body)
}
