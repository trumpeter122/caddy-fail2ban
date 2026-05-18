package caddy_fail2ban

import (
	"fmt"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Fail2Ban{})
}

// Fail2Ban implements an HTTP handler that checks a specified file for banned
// IPs and matches if they are found
type Fail2Ban struct {
	Banfile  string `json:"banfile"`
	Header   string `json:"header,omitempty"`
	logger   *zap.Logger
	banlist  Banlist
}

// CaddyModule returns the Caddy module information.
func (Fail2Ban) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.fail2ban",
		New: func() caddy.Module { return new(Fail2Ban) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Fail2Ban) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.banlist = NewBanlist(ctx, m.logger, &m.Banfile)
	m.banlist.Start()
	return nil
}

func (m *Fail2Ban) Match(req *http.Request) bool {
	remoteIP := ""

	if m.Header != "" {
		remoteIP = req.Header.Get(m.Header)
	}

	if remoteIP == "" {
		var err error
		remoteIP, _, err = net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			m.logger.Error("Error parsing remote addr into IP & port",
				zap.String("remote_addr", req.RemoteAddr),
				zap.Error(err),
			)
			return true
		}
	}

	_, ok := req.Header["X-Caddy-Ban"]
	if ok {
		m.logger.Info("banned IP", zap.String("remote_ip", remoteIP))
		return true
	}

	if m.banlist.IsBanned(remoteIP) {
		m.logger.Info("banned IP", zap.String("remote_ip", remoteIP))
		return true
	}

	m.logger.Debug("received request", zap.String("remote_ip", remoteIP))
	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Fail2Ban) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		switch v := d.Val(); v {
		case "fail2ban":
			if !d.NextArg() {
				return fmt.Errorf("fail2ban expects file path, value is missing")
			}
			m.Banfile = d.Val()

			if d.NextArg() {
				m.Header = d.Val()
			}

			if d.NextArg() {
				return fmt.Errorf("fail2ban expects at most 2 arguments: banfile and optional header")
			}
		default:
			return fmt.Errorf("unknown config value: %s", v)
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner        = (*Fail2Ban)(nil)
	_ caddyhttp.RequestMatcher = (*Fail2Ban)(nil)
	_ caddyfile.Unmarshaler    = (*Fail2Ban)(nil)
)
