// +build root_integration

/*
Copyright 2021 Gravitational, Inc.

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

package integration

import (
	"context"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/regular"
	"github.com/gravitational/teleport/lib/srv/uacc"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"gopkg.in/check.v1"
	. "gopkg.in/check.v1"
)

// teleportTestUser is additional user used for tests
const teleportTestUser = "teleport-test"

// wildcardAllow is used in tests to allow access to all labels.
var wildcardAllow = services.Labels{
	services.Wildcard: []string{services.Wildcard},
}

var _ = check.Suite(&SrvSuite{})

type SrvSuite struct {
	srv        *regular.Server
	signer     ssh.Signer
	server     *auth.TestTLSServer
	testServer *auth.TestAuthServer
}

// TestUTMP tests that user accounting is done on supported systems.
func (s *SrvSuite) TestUTMPEntryExists(c *C) {
	up, err := s.newUpack(teleportTestUser, []string{teleportTestUser}, wildcardAllow)
	c.Assert(err, IsNil)

	sshConfig2 := &ssh.ClientConfig{
		User:            teleportTestUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(up.certSigner)},
		HostKeyCallback: ssh.FixedHostKey(s.signer.PublicKey()),
	}

	client, err := ssh.Dial("tcp", s.srv.Addr(), sshConfig2)
	c.Assert(err, IsNil)
	defer func() {
		err := client.Close()
		c.Assert(err, IsNil)
	}()

	se, err := client.NewSession()
	c.Assert(err, IsNil)
	defer se.Close()

	c.Assert(se.RequestPty("xterm", 30, 30, ssh.TerminalModes{}), IsNil)
	entryExists, err := uacc.UserWithPtyInDatabase(teleportTestUser)
	c.Assert(err, IsNil)
	c.Assert(entryExists, Equals, true)
}

// upack holds all ssh signing artefacts needed for signing and checking user keys
type upack struct {
	// key is a raw private user key
	key []byte

	// pkey is parsed private SSH key
	pkey interface{}

	// pub is a public user key
	pub []byte

	//cert is a certificate signed by user CA
	cert []byte
	// pcert is a parsed ssh Certificae
	pcert *ssh.Certificate

	// signer is a signer that answers signing challenges using private key
	signer ssh.Signer

	// certSigner is a signer that answers signing challenges using private
	// key and a certificate issued by user certificate authority
	certSigner ssh.Signer
}

func (s *SrvSuite) newUpack(username string, allowedLogins []string, allowedLabels services.Labels) (*upack, error) {
	ctx := context.Background()
	auth := s.server.Auth()
	upriv, upub, err := auth.GenerateKeyPair("")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := services.NewUser(username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	role := services.RoleForUser(user)
	rules := role.GetRules(services.Allow)
	rules = append(rules, services.NewRule(services.Wildcard, services.RW()))
	role.SetRules(services.Allow, rules)
	opts := role.GetOptions()
	opts.PermitX11Forwarding = services.NewBool(true)
	role.SetOptions(opts)
	role.SetLogins(services.Allow, allowedLogins)
	role.SetNodeLabels(services.Allow, allowedLabels)
	err = auth.UpsertRole(ctx, role)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user.AddRole(role.GetName())
	err = auth.UpsertUser(user)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	ucert, err := s.testServer.GenerateUserCert(upub, user.GetName(), 5*time.Minute, teleport.CertificateFormatStandard)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	upkey, err := ssh.ParseRawPrivateKey(upriv)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	usigner, err := ssh.NewSignerFromKey(upkey)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	pcert, _, _, _, err := ssh.ParseAuthorizedKey(ucert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ucertSigner, err := ssh.NewCertSigner(pcert.(*ssh.Certificate), usigner)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &upack{
		key:        upriv,
		pkey:       upkey,
		pub:        upub,
		cert:       ucert,
		pcert:      pcert.(*ssh.Certificate),
		signer:     usigner,
		certSigner: ucertSigner,
	}, nil
}
