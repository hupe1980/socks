package socks

import "context"

type socks4Handler struct {
	*logger
	*socksConn
	dialer Dialer
}

func (h *socks4Handler) handle() error {
	req := &Socks4Request{}
	if err := h.read(req); err != nil {
		return err
	}

	switch req.CMD {
	case ConnectCommand:
		return h.handleConnect(req)
	case BindCommand, AssociateCommand:
		fallthrough
	default:
		if err := h.write(&Socks4Response{
			Status: Socks4StatusRejected,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (h *socks4Handler) handleConnect(req *Socks4Request) error {
	target, err := h.dialer.DialContext(context.Background(), "tcp", req.Addr)
	if err != nil {
		if err := h.write(&Socks4Response{
			Status: Socks4StatusRejected,
		}); err != nil {
			return err
		}

		return nil
	}

	defer func() {
		_ = target.Close()
	}()

	if err := h.write(&Socks4Response{
		Status: Socks4StatusGranted,
		Addr:   req.Addr,
	}); err != nil {
		return err
	}

	return h.proxy(target)
}

type socks5Handler struct {
	*logger
	*socksConn
	dialer Dialer
}

func (h *socks5Handler) handle() error {
	methodSelectReq := &MethodSelectRequest{}
	if err := h.read(methodSelectReq); err != nil {
		return err
	}

	if err := h.write(&MethodSelectResponse{
		Version: Socks5Version,
		Method:  AuthMethodNotRequired,
	}); err != nil {
		return err
	}

	req := &Socks5Request{}
	if err := h.read(req); err != nil {
		return err
	}

	switch req.CMD {
	case ConnectCommand:
		return h.handleConnect(req)
	case BindCommand, AssociateCommand:
		fallthrough
	default:
		if err := h.write(&Socks5Response{
			Version: Socks5Version,
			Status:  Socks5StatusCMDNotSupported,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (h *socks5Handler) handleConnect(req *Socks5Request) error {
	target, err := h.dialer.DialContext(context.Background(), "tcp", req.Addr)
	if err != nil {
		if err := h.write(&Socks5Response{
			Version: Socks5Version,
			Status:  Socks5StatusHostUnreachable, //?
		}); err != nil {
			return err
		}

		return nil
	}

	defer func() {
		_ = target.Close()
	}()

	if err := h.write(&Socks5Response{
		Version: Socks5Version,
		Status:  Socks5StatusGranted,
	}); err != nil {
		return err
	}

	return h.proxy(target)
}
