package rest

import (
	"context"
	"net"
	"net/http"
	"os"
	"path"
)

func NewUnixListener(unixSockAddr string) (net.Listener, error) {
	if err := os.Remove(unixSockAddr); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	addrDir := path.Dir(unixSockAddr)
	_, err := os.Stat(addrDir)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(addrDir, 0755); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	unixListener, err := net.Listen("unix", unixSockAddr)
	if err != nil {
		return nil, err
	}
	return unixListener, nil
}

func NewHttpClientUnix(unixSockAddr string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", unixSockAddr)
	}}}
}
