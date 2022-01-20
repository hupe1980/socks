package socks

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSocks4Connect(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		listen, err := net.Listen("tcp", "localhost:0")
		assert.NoError(t, err)

		defer listen.Close()

		server := New()

		go func() {
			_ = server.Serve(listen)
		}()

		cli := testServer.Client()
		cli.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := NewSocks4Dialer("tcp", listen.Addr().String())
				return d.DialContext(ctx, network, addr)
			},
		}
		resp, err := cli.Get(testServer.URL)
		assert.NoError(t, err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)

		assert.Equal(t, "hello", string(body))
	})
}
