package socks

import (
	"context"
	"encoding"
	"io"
	"net"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type socksConn struct {
	reader io.Reader
	writer io.Writer
}

func (c *socksConn) read(req encoding.BinaryUnmarshaler) error {
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

func (c *socksConn) write(resp encoding.BinaryMarshaler) error {
	b, err := resp.MarshalBinary()
	if err != nil {
		return err
	}

	if _, err := c.writer.Write(b); err != nil {
		return err
	}

	return nil
}

func (c *socksConn) connect(target net.Conn) error {
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
