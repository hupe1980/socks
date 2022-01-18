package socks

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSocks4Request(t *testing.T) {
	t.Run("v4", func(t *testing.T) {
		req := &Socks4Request{
			Version: Socks4Version,
			CMD:     ConnectCommand,
			Addr:    "127.0.0.1:8080",
		}

		b, err := req.MarshalBinary()
		assert.NoError(t, err)

		req2 := &Socks4Request{}
		err = req2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, req, req2)
	})

	t.Run("v4 with userID", func(t *testing.T) {
		req := &Socks4Request{
			Version: Socks4Version,
			CMD:     ConnectCommand,
			Addr:    "127.0.0.1:8080",
			UserID:  "xyz",
		}

		b, err := req.MarshalBinary()
		assert.NoError(t, err)

		req2 := &Socks4Request{}
		err = req2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, req, req2)
	})

	t.Run("v4a", func(t *testing.T) {
		req := &Socks4Request{
			Version: Socks4Version,
			CMD:     ConnectCommand,
			Addr:    "localhost:8080",
		}

		b, err := req.MarshalBinary()
		assert.NoError(t, err)

		req2 := &Socks4Request{}
		err = req2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, req, req2)
	})

	t.Run("v4a with userID", func(t *testing.T) {
		req := &Socks4Request{
			Version: Socks4Version,
			CMD:     ConnectCommand,
			Addr:    "localhost:8080",
			UserID:  "xyz",
		}

		b, err := req.MarshalBinary()
		assert.NoError(t, err)

		req2 := &Socks4Request{}
		err = req2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, req, req2)
	})
}

func TestSocks4Response(t *testing.T) {
	t.Run("connect", func(t *testing.T) {
		resp := &Socks4Response{
			Status: Socks4StatusGranted,
		}

		b, err := resp.MarshalBinary()
		assert.NoError(t, err)

		resp2 := &Socks4Response{}
		err = resp2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, resp, resp2)
	}) // TODO BIND
}

func TestMethodSelectRequest(t *testing.T) {
	t.Run("single method", func(t *testing.T) {
		req := &MethodSelectRequest{
			Version: Socks5Version,
			Methods: []AuthMethod{AuthMethodNotRequired},
		}

		b, err := req.MarshalBinary()
		assert.NoError(t, err)

		req2 := &MethodSelectRequest{}
		err = req2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, req, req2)
	})

	t.Run("multi methods", func(t *testing.T) {
		req := &MethodSelectRequest{
			Version: Socks5Version,
			Methods: []AuthMethod{AuthMethodNotRequired, AuthMethodUsernamePassword},
		}

		b, err := req.MarshalBinary()
		assert.NoError(t, err)

		req2 := &MethodSelectRequest{}
		err = req2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, req, req2)
	})
}

func TestMethodSelectResponse(t *testing.T) {
	resp := &MethodSelectResponse{
		Version: Socks5Version,
		Method:  AuthMethodNotRequired,
	}

	b, err := resp.MarshalBinary()
	assert.NoError(t, err)

	resp2 := &MethodSelectResponse{}
	err = resp2.UnmarshalBinary(b)
	assert.NoError(t, err)

	assert.Equal(t, resp, resp2)
}

func TestUsernamePasswordAuthRequest(t *testing.T) {
	req := &UsernamePasswordAuthRequest{
		Version:  UsernamePasswordAuthVersion1,
		Username: "User",
		Password: "Pass",
	}

	b, err := req.MarshalBinary()
	assert.NoError(t, err)

	req2 := &UsernamePasswordAuthRequest{}
	err = req2.UnmarshalBinary(b)
	assert.NoError(t, err)

	assert.Equal(t, req, req2)
}

func TestUsernamePasswordAuthResponse(t *testing.T) {
	resp := &UsernamePasswordAuthResponse{
		Version: UsernamePasswordAuthVersion1,
		Status:  AuthStatusSuccess,
	}

	b, err := resp.MarshalBinary()
	assert.NoError(t, err)

	resp2 := &UsernamePasswordAuthResponse{}
	err = resp2.UnmarshalBinary(b)
	assert.NoError(t, err)

	assert.Equal(t, resp, resp2)
}

func TestSocks5Request(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		req := &Socks5Request{
			Version: Socks5Version,
			CMD:     ConnectCommand,
			Addr:    "127.0.0.1:8080",
		}

		b, err := req.MarshalBinary()
		assert.NoError(t, err)

		req2 := &Socks5Request{}
		err = req2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, req, req2)
	})

	t.Run("IPv4", func(t *testing.T) {
		req := &Socks5Request{
			Version: Socks5Version,
			CMD:     ConnectCommand,
			Addr:    "[::1]:8080",
		}

		b, err := req.MarshalBinary()
		assert.NoError(t, err)

		req2 := &Socks5Request{}
		err = req2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, req, req2)
	})

	t.Run("FQDN", func(t *testing.T) {
		req := &Socks5Request{
			Version: Socks5Version,
			CMD:     ConnectCommand,
			Addr:    "localhost:8080",
		}

		b, err := req.MarshalBinary()
		assert.NoError(t, err)

		req2 := &Socks5Request{}
		err = req2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, req, req2)
	})
}

func TestSocks5Response(t *testing.T) {
	t.Run("connect", func(t *testing.T) {
		resp := &Socks5Response{
			Version: Socks5Version,
			Status:  Socks5StatusGranted,
		}

		b, err := resp.MarshalBinary()
		assert.NoError(t, err)

		resp2 := &Socks5Response{}
		err = resp2.UnmarshalBinary(b)
		assert.NoError(t, err)

		assert.Equal(t, resp, resp2)
	}) // TODO BIND / Addr
}
