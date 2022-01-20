package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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
			Proxy: func(request *http.Request) (*url.URL, error) {
				return url.Parse("socks5://localhost:1080")
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
