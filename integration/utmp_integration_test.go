//+build test_as_root

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
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/bpf"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/pam"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/regular"
	"github.com/gravitational/teleport/lib/srv/uacc"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	. "gopkg.in/check.v1"
)

// teleportTestUser is additional user used for tests
const teleportTestUser = "teleport-test"

// wildcardAllow is used in tests to allow access to all labels.
var wildcardAllow = services.Labels{
	services.Wildcard: []string{services.Wildcard},
}

type SrvCtx struct {
	srv        *regular.Server
	signer     ssh.Signer
	server     *auth.TestTLSServer
	testServer *auth.TestAuthServer
	clock      clockwork.FakeClock
	nodeClient *auth.Client
	nodeID     string
}

// TestUTMP tests that user accounting is done on supported systems.
func TestUTMPEntryExists(t *testing.T) {
	s := &SrvCtx{}
	s.SetUpContext(t)
	up, err := s.newUpack(teleportTestUser, []string{teleportTestUser}, wildcardAllow)
	require.NoError(t, err)

	sshConfig2 := &ssh.ClientConfig{
		User:            teleportTestUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(up.certSigner)},
		HostKeyCallback: ssh.FixedHostKey(s.signer.PublicKey()),
	}

	client, err := ssh.Dial("tcp", s.srv.Addr(), sshConfig2)
	require.NoError(t, err)
	defer func() {
		err := client.Close()
		require.NoError(t, err)
	}()

	se, err := client.NewSession()
	require.NoError(t, err)
	defer se.Close()

	require.NoError(t, se.RequestPty("xterm", 30, 30, ssh.TerminalModes{}), nil)
	entryExists, err := uacc.UserWithPtyInDatabase(teleportTestUser)
	require.NoError(t, err)
	require.Equal(t, entryExists, true)
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

const hostID = "00000000-0000-0000-0000-000000000000"

func (s *SrvCtx) SetUpContext(t *testing.T) {
	s.clock = clockwork.NewFakeClock()
	tempdir, err := ioutil.TempDir("", "utmp-integration")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)

	authServer, err := auth.NewTestAuthServer(auth.TestAuthServerConfig{
		ClusterName: "localhost",
		Dir:         tempdir,
		Clock:       s.clock,
	})
	require.NoError(t, err)
	s.server, err = authServer.NewTestTLSServer()
	require.NoError(t, err)
	s.testServer = authServer

	// set up host private key and certificate
	certs, err := s.server.Auth().GenerateServerKeys(auth.GenerateServerKeysRequest{
		HostID:   hostID,
		NodeName: s.server.ClusterName(),
		Roles:    teleport.Roles{teleport.RoleNode},
	})
	require.NoError(t, err)

	// set up user CA and set up a user that has access to the server
	s.signer, err = sshutils.NewSigner(certs.Key, certs.Cert)
	require.NoError(t, err)

	s.nodeID = uuid.New()
	s.nodeClient, err = s.server.NewClient(auth.TestIdentity{
		I: auth.BuiltinRole{
			Role:     teleport.RoleNode,
			Username: s.nodeID,
		},
	})
	require.NoError(t, err)

	nodeDir, err := ioutil.TempDir("", "utmp-integration")
	require.NoError(t, err)
	defer os.RemoveAll(tempdir)
	srv, err := regular.New(
		utils.NetAddr{AddrNetwork: "tcp", Addr: "127.0.0.1:0"},
		s.server.ClusterName(),
		[]ssh.Signer{s.signer},
		s.nodeClient,
		nodeDir,
		"",
		utils.NetAddr{},
		regular.SetUUID(s.nodeID),
		regular.SetNamespace(defaults.Namespace),
		regular.SetEmitter(s.nodeClient),
		regular.SetShell("/bin/sh"),
		regular.SetSessionServer(s.nodeClient),
		regular.SetPAMConfig(&pam.Config{Enabled: false}),
		regular.SetLabels(
			map[string]string{"foo": "bar"},
			services.CommandLabels{
				"baz": &services.CommandLabelV2{
					Period:  services.NewDuration(time.Millisecond),
					Command: []string{"expr", "1", "+", "3"}},
			},
		),
		regular.SetBPF(&bpf.NOP{}),
		regular.SetClock(s.clock),
	)
	require.NoError(t, err)
	s.srv = srv
	require.NoError(t, auth.CreateUploaderDir(nodeDir), IsNil)
	require.NoError(t, s.srv.Start())
}

func (s *SrvCtx) newUpack(username string, allowedLogins []string, allowedLabels services.Labels) (*upack, error) {
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
