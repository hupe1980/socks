package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Version byte

const (
	Socks4Version Version = 0x04
	Socks5Version Version = 0x05
)

type Command uint8

const (
	ConnectCommand   Command = 0x01
	BindCommand      Command = 0x02
	AssociateCommand Command = 0x03
)

func (cmd Command) String() string {
	switch cmd {
	case ConnectCommand:
		return "socks connect"
	case BindCommand:
		return "socks bind"
	case AssociateCommand:
		return "socks associate"
	default:
		return "socks " + strconv.Itoa(int(cmd))
	}
}

type Socks4Status uint8

const (
	Socks4StatusGranted       Socks4Status = 0x5a
	Socks4StatusRejected      Socks4Status = 0x5b
	Socks4StatusNoIdentd      Socks4Status = 0x5c
	Socks4StatusInvalidUserID Socks4Status = 0x5d
)

type Socks5Status uint8

const (
	Socks5StatusGranted              Socks5Status = 0x00
	Socks5StatusFailure              Socks5Status = 0x01
	Socks5StatusNotAllowed           Socks5Status = 0x02
	Socks5StatusNetworkUnreaachable  Socks5Status = 0x03
	Socks5StatusHostUnreachable      Socks5Status = 0x04
	Socks5StatusConnectionRefused    Socks5Status = 0x05
	Socks5StatusTTLExpired           Socks5Status = 0x06
	Socks5StatusCMDNotSupported      Socks5Status = 0x07
	Socks5StatusAddrTypeNotSupported Socks5Status = 0x08
)

type AddrType uint8

const (
	AddrTypeIPv4 AddrType = 0x01
	AddrTypeFQDN AddrType = 0x03
	AddrTypeIPv6 AddrType = 0x04
)

type UsernamePasswordAuthVersion uint8

const (
	UsernamePasswordAuthVersion1 = 0x01
)

type AuthMethod uint8

const (
	AuthMethodNotRequired         AuthMethod = 0x00 // no authentication required
	AuthMethodUsernamePassword    AuthMethod = 0x02 // use username/password
	AuthMethodNoAcceptableMethods AuthMethod = 0xff // no acceptable authentication methods
)

type AuthStatus uint8

const (
	AuthStatusSuccess AuthStatus = 0x00
	AuthStatusFailure AuthStatus = 0xff
)

type AuthenticateFunc func(context.Context, *Conn, AuthMethod) error

type Socks4Request struct {
	Version Version
	CMD     Command
	Addr    string
	UserID  string
}

func (req *Socks4Request) MarshalBinary() ([]byte, error) {
	b := []byte{byte(req.Version), byte(req.CMD)}

	host, port, err := splitHostPort(req.Addr)
	if err != nil {
		return nil, err
	}

	dstIP := make([]byte, 4)

	var domain string

	if ip := net.ParseIP(host); ip != nil {
		dstIP = ip.To4()
	} else {
		dstIP[0] = 0
		dstIP[1] = 0
		dstIP[2] = 0
		dstIP[3] = 1

		domain = host
	}

	b = append(b, byte(port>>8), byte(port))

	b = append(b, dstIP...)

	if req.UserID != "" {
		b = append(b, []byte(req.UserID)...)
	}

	b = append(b, 0)

	if domain != "" {
		b = append(b, []byte(domain)...)
		b = append(b, 0)
	}

	return b, nil
}

func (req *Socks4Request) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	version := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return err
	}

	req.Version = Version(version[0])

	if req.Version != Socks4Version {
		return fmt.Errorf("unsupported SOCKS version: %d", req.Version)
	}

	cmd := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &cmd); err != nil {
		return err
	}

	req.CMD = Command(cmd[0])

	port := make([]byte, 2)
	if err := binary.Read(r, binary.BigEndian, &port); err != nil {
		return err
	}

	portNum := (int(port[0]) << 8) | int(port[1])

	ip := make(net.IP, 4)
	if err := binary.Read(r, binary.BigEndian, &ip); err != nil {
		return err
	}

	userID, err := r.ReadString(0)
	if err != nil {
		return err
	}

	req.UserID = strings.TrimSuffix(userID, "\x00")

	socks4a := (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0)

	req.Addr = net.JoinHostPort(ip.String(), strconv.Itoa(portNum))

	if socks4a {
		domain, err := r.ReadString(0)
		if err != nil {
			return err
		}

		req.Addr = net.JoinHostPort(strings.TrimSuffix(domain, "\x00"), strconv.Itoa(portNum))
	}

	return nil
}

type Socks4Response struct {
	Status Socks4Status
	Addr   string
}

func (resp *Socks4Response) MarshalBinary() ([]byte, error) {
	b := []byte{0, byte(resp.Status)}

	if resp.Addr == "" {
		b = append(b, []byte{0, 0, 0, 0, 0, 0}...)
	}

	// TODO BIND
	// _, port, err := splitHostPort(resp.Addr)
	// if err != nil {
	// 	return nil, err
	// }

	// b = append(b, byte(port>>8), byte(port))

	// b = append(b, net.IP{127, 0, 0, 1}...)

	return b, nil
}

func (resp *Socks4Response) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p[1:]) // ignore version

	status := make([]byte, 1)

	if err := binary.Read(r, binary.BigEndian, &status); err != nil {
		return err
	}

	resp.Status = Socks4Status(status[0])

	return nil
}

type MethodSelectRequest struct {
	Version Version
	Methods []AuthMethod
}

func (req *MethodSelectRequest) MarshalBinary() ([]byte, error) {
	b := []byte{byte(req.Version), byte(len(req.Methods))}

	for _, m := range req.Methods {
		b = append(b, byte(m))
	}

	return b, nil
}

func (req *MethodSelectRequest) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	version := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return err
	}

	req.Version = Version(version[0])

	number := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &number); err != nil {
		return err
	}

	methods := make([]byte, int(number[0]))
	if err := binary.Read(r, binary.BigEndian, &methods); err != nil {
		return err
	}

	for _, m := range methods {
		req.Methods = append(req.Methods, AuthMethod(m))
	}

	return nil
}

type MethodSelectResponse struct {
	Version Version
	Method  AuthMethod
}

func (resp *MethodSelectResponse) MarshalBinary() ([]byte, error) {
	return []byte{byte(resp.Version), byte(resp.Method)}, nil
}

func (resp *MethodSelectResponse) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	version := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return err
	}

	resp.Version = Version(version[0])

	method := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &method); err != nil {
		return err
	}

	resp.Method = AuthMethod(method[0])

	return nil
}

type UsernamePasswordAuthRequest struct {
	Version  UsernamePasswordAuthVersion
	Username string
	Password string
}

func (req *UsernamePasswordAuthRequest) MarshalBinary() ([]byte, error) {
	b := []byte{byte(req.Version)}

	b = append(b, byte(len(req.Username)))
	b = append(b, []byte(req.Username)...)

	b = append(b, byte(len(req.Password)))
	b = append(b, []byte(req.Password)...)

	return b, nil
}

func (req *UsernamePasswordAuthRequest) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	version := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return err
	}

	req.Version = UsernamePasswordAuthVersion(version[0])

	length := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}

	username := make([]byte, length[0])
	if err := binary.Read(r, binary.BigEndian, &username); err != nil {
		return err
	}

	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return err
	}

	req.Username = string(username)

	password := make([]byte, length[0])
	if err := binary.Read(r, binary.BigEndian, &password); err != nil {
		return err
	}

	req.Password = string(password)

	return nil
}

type UsernamePasswordAuthResponse struct {
	Version UsernamePasswordAuthVersion
	Status  AuthStatus
}

func (resp *UsernamePasswordAuthResponse) MarshalBinary() ([]byte, error) {
	return []byte{byte(resp.Version), byte(resp.Status)}, nil
}

func (resp *UsernamePasswordAuthResponse) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	version := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return err
	}

	resp.Version = UsernamePasswordAuthVersion(version[0])

	status := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &status); err != nil {
		return err
	}

	resp.Status = AuthStatus(status[0])

	return nil
}

type Socks5Request struct {
	Version Version
	CMD     Command
	Addr    string
}

func (req *Socks5Request) MarshalBinary() ([]byte, error) {
	b := []byte{byte(req.Version), byte(req.CMD), 0}

	host, port, err := splitHostPort(req.Addr)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(b, byte(AddrTypeIPv4))
			b = append(b, ip4...)
		} else if ip6 := ip.To16(); ip6 != nil {
			b = append(b, byte(AddrTypeIPv6))
			b = append(b, ip6...)
		} else {
			return nil, errors.New("unknown address type")
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("FQDN too long")
		}
		b = append(b, byte(AddrTypeFQDN))
		b = append(b, byte(len(host)))
		b = append(b, host...)
	}

	b = append(b, byte(port>>8), byte(port))

	return b, nil
}

func (req *Socks5Request) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	version := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return err
	}

	req.Version = Version(version[0])

	if req.Version != Socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", req.Version)
	}

	cmd := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &cmd); err != nil {
		return err
	}

	req.CMD = Command(cmd[0])

	if _, err := r.ReadByte(); err != nil { // null byte
		return err
	}

	atype := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &atype); err != nil {
		return err
	}

	var host string

	switch AddrType(atype[0]) {
	case AddrTypeIPv4:
		ip := make(net.IP, net.IPv4len)
		if err := binary.Read(r, binary.BigEndian, &ip); err != nil {
			return err
		}

		host = ip.String()
	case AddrTypeIPv6:
		ip := make(net.IP, net.IPv6len)
		if err := binary.Read(r, binary.BigEndian, &ip); err != nil {
			return err
		}

		host = ip.String()
	case AddrTypeFQDN:
		length := make([]byte, 1)
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return err
		}

		fqdn := make([]byte, length[0])
		if err := binary.Read(r, binary.BigEndian, &fqdn); err != nil {
			return err
		}

		host = string(fqdn)
	default:
		return fmt.Errorf("unknown address type %x", atype[0])
	}

	port := make([]byte, 2)
	if err := binary.Read(r, binary.BigEndian, &port); err != nil {
		return err
	}

	portNum := (int(port[0]) << 8) | int(port[1])

	req.Addr = net.JoinHostPort(host, strconv.Itoa(portNum))

	return nil
}

type Socks5Response struct {
	Version Version
	Status  Socks5Status
	Addr    string
}

func (resp *Socks5Response) MarshalBinary() ([]byte, error) {
	b := []byte{byte(resp.Version), byte(resp.Status), 0}

	return b, nil
}

func (resp *Socks5Response) UnmarshalBinary(p []byte) error {
	r := bytes.NewBuffer(p)

	version := make([]byte, 1)
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return err
	}

	resp.Version = Version(version[0])

	return nil
}

func splitHostPort(address string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}

	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", 0, err
	}

	if 1 > portnum || portnum > 0xffff {
		return "", 0, errors.New("port number out of range " + port)
	}

	return host, uint16(portnum), nil
}
