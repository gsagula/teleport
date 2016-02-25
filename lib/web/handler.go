/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package web

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/roundtrip"
	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"
	"github.com/mailgun/ttlmap"
)

// Handler is HTTP web proxy handler
type Handler struct {
	httprouter.Router
	cfg   Config
	auth  *sessionHandler
	sites *ttlmap.TtlMap
	sync.Mutex
}

// Config represents web handler configuration parameters
type Config struct {
	// InsecureHTTPMode tells whether handler is running
	// in HTTP only that is considered insecure (as opposed to HTTPS)
	InsecureHTTPMode bool
	// Proxy is a reverse tunnel proxy that handles connections
	// to various sites
	Proxy reversetunnel.Server
	// AssetsDir is a directory with web assets (js files, css files)
	AssetsDir string
	// AuthServers is a list of auth servers this proxy talks to
	AuthServers utils.NetAddr
	// DomainName is a domain name served by web handler
	DomainName string
}

// Version is a current webapi version
const Version = "v1"

// HewHandler returns a new instance of web proxy handler
func NewHandler(cfg Config) (http.Handler, error) {
	lauth, err := newSessionHandler(!cfg.InsecureHTTPMode, []utils.NetAddr{cfg.AuthServers})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	h := &Handler{
		cfg:  cfg,
		auth: lauth,
	}

	// Web sessions
	h.POST("/webapi/sessions", httplib.MakeHandler(h.createSession))
	h.DELETE("/webapi/sessions/:sid", h.withAuth(h.deleteSession))

	// Users
	h.GET("/webapi/users/invites/:token", httplib.MakeHandler(h.renderUserInvite))
	h.POST("/webapi/users", httplib.MakeHandler(h.createNewUser))

	// Issues SSH temp certificates based on 2FA access creds
	h.POST("/webapi/ssh/certs", httplib.MakeHandler(h.createSSHCert))

	// list available sites
	h.GET("/webapi/sites", h.withAuth(h.getSites))

	// Site specific API

	routingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/web/app") {
			http.StripPrefix("/web", http.FileServer(http.Dir(cfg.AssetsDir))).ServeHTTP(w, r)
		} else if strings.HasPrefix(r.URL.Path, "/web") {
			http.ServeFile(w, r, filepath.Join(cfg.AssetsDir, "/index.html"))
		} else if strings.HasPrefix(r.URL.Path, "/"+Version) {
			http.StripPrefix("/"+Version, h).ServeHTTP(w, r)
		}
	})

	return routingHandler, nil
}

// createSessionReq is a request to create session from username, password and second
// factor token
type createSessionReq struct {
	User              string `json:"user"`
	Pass              string `json:"pass"`
	SecondFactorToken string `json:"second_factor_token"`
}

// createSessionResponse returns OAuth compabible data about
// access token: https://tools.ietf.org/html/rfc6749
type createSessionResponse struct {
	// Type is token type (bearer)
	Type string `json:"type"`
	// Token value
	Token string `json:"token"`
	// User represents the user
	User string `json:"user"`
	// ExpiresIn sets seconds before this token is not valid
	ExpiresIn int `json:"expires_in"`
}

// createSession creates a new web session based on user, pass and 2nd factor token
//
// POST /v1/webapi/sessions
//
// {"user": "alex", "pass": "abc123", "second_factor_token": "token"}
//
// Response
//
// {"type": "bearer", "token": "bearer token", "user": "alex", "expires_in": 20}
//
func (m *Handler) createSession(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
	var req *createSessionReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	sess, err := m.auth.Auth(req.User, req.Pass, req.SecondFactorToken)
	if err != nil {
		log.Infof("bad access credentials: %v", err)
		return nil, trace.Wrap(teleport.AccessDenied("bad auth credentials"))
	}
	if err := SetSession(w, req.User, sess.ID); err != nil {
		return nil, trace.Wrap(err)
	}
	return &createSessionResponse{
		Type:      roundtrip.AuthBearer,
		Token:     sess.ID,
		User:      req.User,
		ExpiresIn: int(time.Now().Sub(sess.WS.Expires) / time.Second),
	}, nil
}

// deleteSession is called to sign out user
//
// DELETE /v1/webapi/sessions/:sid
//
// Response:
//
// {"message": "ok"}
//
func (m *Handler) deleteSession(w http.ResponseWriter, r *http.Request, _ httprouter.Params, ctx *sessionContext) (interface{}, error) {
	clt, err := ctx.GetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sess := ctx.GetWebSession()
	if err := clt.DeleteWebSession(ctx.GetUser(), sess.ID); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := ClearSession(w); err != nil {
		return nil, trace.Wrap(err)
	}
	return ok(), nil
}

type renderUserInviteResponse struct {
	InviteToken string `json:"invite_token"`
	User        string `json:"user"`
	QR          []byte `json:"qr"`
}

// renderUserInvite is called to show user the new user invitation page
//
// GET /v1/webapi/users/invites/:token
//
// Response:
//
// {"invite_token": "token", "user": "alex", qr: "base64-encoded-qr-code image"}
//
//
func (m *Handler) renderUserInvite(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
	token := p[0].Value
	user, QRCodeBytes, _, err := m.auth.GetUserInviteInfo(token)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &renderUserInviteResponse{
		InviteToken: token,
		User:        user,
		QR:          QRCodeBytes,
	}, nil
}

// createNewUser req is a request to create a new Teleport user
type createNewUserReq struct {
	InviteToken       string `json:"invite_token"`
	Pass              string `json:"pass"`
	SecondFactorToken string `json:"second_factor_token"`
}

// createNewUser creates new user entry based on the invite token
//
// POST /v1/webapi/users
//
// {"invite_token": "unique invite token", "pass": "user password", "second_factor_token": "valid second factor token"}
//
// Sucessful response: (session cookie is set)
//
// {"type": "bearer", "token": "bearer token", "user": "alex", "expires_in": 20}
func (m *Handler) createNewUser(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
	var req *createNewUserReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	sess, err := m.auth.CreateNewUser(req.InviteToken, req.Pass, req.SecondFactorToken)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := SetSession(w, sess.User, sess.ID); err != nil {
		return nil, trace.Wrap(err)
	}
	return &createSessionResponse{
		Type:      roundtrip.AuthBearer,
		Token:     sess.ID,
		User:      sess.User,
		ExpiresIn: int(time.Now().Sub(sess.WS.Expires) / time.Second),
	}, nil
}

type getSitesResponse struct {
	Sites []site `json:"sites"`
}

type site struct {
	Name          string    `json:"name"`
	LastConnected time.Time `json:"last_connected"`
	Status        string    `json:"status"`
}

func convertSites(rs []reversetunnel.RemoteSite) []site {
	out := make([]site, len(rs))
	for i := range rs {
		out[i] = site{
			Name:          rs[i].GetName(),
			LastConnected: rs[i].GetLastConnected(),
			Status:        rs[i].GetStatus(),
		}
	}
	return out
}

// getSites returns a list of sites
//
// GET /v1/webapi/sites
//
// Sucessful response:
//
// {"sites": {"name": "localhost", "last_connected": "RFC3339 time", "status": "active"}}
//
func (m *Handler) getSites(w http.ResponseWriter, r *http.Request, _ httprouter.Params, c *sessionContext) (interface{}, error) {
	return getSitesResponse{
		Sites: convertSites(m.cfg.Proxy.GetSites()),
	}, nil
}

// createSSHCertReq are passed by web client
// to authenticate against teleport server and receive
// a temporary cert signed by auth server authority
type createSSHCertReq struct {
	// User is a teleport username
	User string `json:"user"`
	// Password is user's pass
	Password string `json:"password"`
	// HOTPToken is second factor token
	HOTPToken string `json:"hotp_token"`
	// PubKey is a public key user wishes to sign
	PubKey []byte `json:"pub_key"`
	// TTL is a desired TTL for the cert (max is still capped by server,
	// however user can shorten the time)
	TTL time.Duration `json:"ttl"`
}

// SSHLoginResponse is a response returned by web proxy
type SSHLoginResponse struct {
	// Cert is a signed certificate
	Cert []byte `json:"cert"`
	// HostSigners is a list of signing host public keys
	// trusted by proxy
	HostSigners []services.CertAuthority `json:"host_signers"`
}

// createSSHCert is a web call that generates new SSH certificate based
// on user's name, password, 2nd factor token and public key user wishes to sign
//
// POST /v1/webapi/ssh/certs
//
// { "user": "bob", "password": "pass", "hotp_token": "tok", "pub_key": "key to sign", "ttl": 1000000000 }
//
// Success response
//
// { "cert": "base64 encoded signed cert", "host_signers": [{"domain_name": "example.com", "checking_keys": ["base64 encoded public signing key"]}] }
//
func (h *Handler) createSSHCert(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
	var req *createSSHCertReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}

	cert, err := h.auth.GetCertificate(*req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return cert, nil
}

func (h *Handler) String() string {
	return fmt.Sprintf("multi site")
}

// contextHandler is a handler called with the auth context, what means it is authenticated and ready to work
type contextHandler func(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *sessionContext) (interface{}, error)

// siteHandler is a authenticated handler that is called for some existing remote site
type siteHandler func(w http.ResponseWriter, r *http.Request, p httprouter.Params, ctx *sessionContext, site reversetunnel.RemoteSite) (interface{}, error)

// withSiteAuth ensures that request is authenticated and is issued for existing site
func (h *Handler) withSiteAuth(fn siteHandler) httprouter.Handle {
	return httplib.MakeHandler(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
		ctx, err := h.authenticateRequest(r)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		siteName := p.ByName("site")
		site, err := h.cfg.Proxy.GetSite(siteName)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return fn(w, r, p, ctx, site)
	})
}

// withAuth ensures that request is authenticated
func (h *Handler) withAuth(fn contextHandler) httprouter.Handle {
	return httplib.MakeHandler(func(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
		ctx, err := h.authenticateRequest(r)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return fn(w, r, p, ctx)
	})
}

// authenticateRequest authenticates request using combination of a session cookie
// and bearer token
func (h *Handler) authenticateRequest(r *http.Request) (*sessionContext, error) {
	logger := log.WithFields(log.Fields{
		"request": fmt.Sprintf("%v %v", r.Method, r.URL.String()),
	})
	logger.Infof("incoming request")
	cookie, err := r.Cookie("session")
	if err != nil {
		logger.Warningf("missing cookie: %v", err)
		return nil, trace.Wrap(teleport.AccessDenied("missing cookie"))
	}
	d, err := DecodeCookie(cookie.Value)
	if err != nil {
		logger.Warningf("failed to decode cookie: %v", err)
		return nil, trace.Wrap(teleport.AccessDenied("failed to decode cookie"))
	}
	creds, err := roundtrip.ParseAuthHeaders(r)
	if err != nil {
		logger.Warningf("no auth headers %v", err)
		return nil, trace.Wrap(teleport.AccessDenied("need auth"))
	}
	ctx, err := h.auth.ValidateSession(d.User, d.SID)
	if err != nil {
		logger.Warningf("invalid session: %v", err)
		return nil, trace.Wrap(teleport.AccessDenied("need auth"))
	}
	if creds.Password != d.SID {
		logger.Warningf("bad auth token")
		return nil, trace.Wrap(teleport.AccessDenied("missing auth token"))
	}
	return ctx, nil
}

func message(msg string) interface{} {
	return map[string]interface{}{"message": msg}
}

func ok() interface{} {
	return message("ok")
}

type Server struct {
	http.Server
}

func New(addr utils.NetAddr, cfg Config) (*Server, error) {
	h, err := NewHandler(cfg)
	if err != nil {
		return nil, err
	}
	srv := &Server{}
	srv.Server.Addr = addr.Addr
	srv.Server.Handler = h
	return srv, nil
}

func CreateSignupLink(hostPort string, token string) string {
	// TODO(klizhentas) HTTPS
	return "http://" + hostPort + "/web/newuser/" + token
}
