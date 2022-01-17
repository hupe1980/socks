package socks

import (
	"bufio"
	"context"
	"encoding"
	"io"
	"net"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Conn struct {
	reader *bufio.Reader
	writer io.Writer
}

func NewConn(conn net.Conn) *Conn {
	return &Conn{
		reader: bufio.NewReader(conn),
		writer: conn,
	}
}

func (c *Conn) Peek(n int) ([]byte, error) {
	return c.reader.Peek(n)
}

func (c *Conn) Read(req encoding.BinaryUnmarshaler) error {
	buff := make([]byte, 1024)

	n, err := c.reader.Read(buff)
	if err != nil {
		return err
	}

	if err := req.UnmarshalBinary(buff[:n]); err != nil {
		return err
	}

	return nil
}

func (c *Conn) Write(resp encoding.BinaryMarshaler) error {
	b, err := resp.MarshalBinary()
	if err != nil {
		return err
	}

	if _, err := c.writer.Write(b); err != nil {
		return err
	}

	return nil
}

func (c *Conn) Connect(target net.Conn) error {
	errCh := make(chan error, 2)

	go proxy(target, c.reader, errCh)
	go proxy(c.writer, target, errCh)

	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			return e
		}
	}

	return nil
}

func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)

	if tcpConn, ok := dst.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}

	errCh <- err
}
