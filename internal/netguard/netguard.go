package netguard

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"
)

// OutboundClient is the one definition of Airlock's outbound HTTP policy: no
// inherited proxy, bounded dial/TLS/response-header timeouts, capped idle
// connections, and refused redirects. Both nodes dial through it.
func OutboundClient(forceAttemptHTTP2 bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 nil, // Never inherit HTTP(S)_PROXY or NO_PROXY.
			DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     forceAttemptHTTP2,
			MaxIdleConns:          2,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   3 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
		},
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are refused")
		},
	}
}

func Listen(address string, unsafeNonLoopback bool) (net.Listener, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("listen address must be an explicit IP and port")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("listen host must be an IP literal")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return nil, errors.New("invalid listen port")
	}
	if !ip.IsLoopback() && !unsafeNonLoopback {
		return nil, errors.New("non-loopback listen refused; pass --unsafe-non-loopback to acknowledge exposure")
	}
	return net.Listen("tcp", address)
}
