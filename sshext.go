package sshext

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/ssh"
)

const (
	// chanSize sets the amount of buffering SSH connections.
	// refs: https://github.com/golang/crypto/blob/master/ssh/handshake.go#L22-L25
	chanSize                  = 16
	requestTypeHostKeys       = "hostkeys-00@openssh.com"
	requestTypeHostKeysProve  = "hostkeys-prove-00@openssh.com"
	requestTypeNoMoreSessions = "no-more-sessions@openssh.com"
)

// NoMoreSessions is an implementation of the SSH Extension Protocol
// refs: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL
func NoMoreSessions(reqs <-chan *ssh.Request) (<-chan *ssh.Request, <-chan struct{}, error) {
	relayed := make(chan *ssh.Request, chanSize)
	noMore := make(chan struct{}, 1)
	go func() {
		for req := range reqs {
			if req.Type == requestTypeNoMoreSessions {
				noMore <- struct{}{}
			} else {
				relayed <- req
			}
		}
		close(relayed)
		close(noMore)
	}()
	return relayed, noMore, nil
}

// UpdateHostKeys is an implementation of the SSH Extension Protocol
// refs: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL
func UpdateHostKeys(conn *ssh.ServerConn, reqs <-chan *ssh.Request, signers []ssh.Signer) (<-chan *ssh.Request, error) {
	err := sendHostKeys(conn, signers)
	if err != nil {
		return reqs, err
	}
	id := conn.SessionID()
	relayed := make(chan *ssh.Request, chanSize)
	go func() {
		for req := range reqs {
			if req.Type == requestTypeHostKeysProve {
				proveOwnership(signers, id, req)
			} else {
				relayed <- req
			}
		}
		close(relayed)
	}()
	return relayed, nil
}

func sendHostKeys(conn *ssh.ServerConn, signers []ssh.Signer) error {
	payload := marshalPublicKeys(signers)
	_, _, err := conn.SendRequest(requestTypeHostKeys, false, payload)
	if err != nil {
		return fmt.Errorf("failed to send request for %s: %s", requestTypeHostKeys, err)
	}
	return nil
}

func marshalPublicKeys(signers []ssh.Signer) []byte {
	var buf bytes.Buffer
	for _, s := range signers {
		raw := s.PublicKey().Marshal()
		msg := wrapStruct(raw)
		buf.Write(ssh.Marshal(msg))
	}
	return buf.Bytes()
}

func wrapStruct(p []byte) struct{ string } {
	return struct {
		string
	}{string: string(p)}
}

func proveOwnership(signers []ssh.Signer, sessionID []byte, req *ssh.Request) {
	keys, err := parsePublicKeys(req.Payload)
	if err != nil {
		_ = req.Reply(false, nil)
		return
	}
	var sigs []*ssh.Signature
	for _, key := range keys {
		known := findKnown(signers, key)
		if known == nil {
			_ = req.Reply(false, nil)
			return
		}
		sig, err := signHostKey(known, key, sessionID)
		if err != nil {
			_ = req.Reply(false, nil)
			return
		}
		sigs = append(sigs, sig)
	}
	_ = req.Reply(true, marshalSignatures(sigs))
}

func marshalSignatures(signatures []*ssh.Signature) []byte {
	var buf bytes.Buffer
	for _, s := range signatures {
		raw := ssh.Marshal(s)
		msg := wrapStruct(raw)
		buf.Write(ssh.Marshal(msg))
	}
	return buf.Bytes()
}

func parsePublicKeys(p []byte) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for len(p) > 0 {
		var msg struct {
			Blob string
			Rest []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(p, &msg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal payload: %s", err)
		}
		key, err := ssh.ParsePublicKey([]byte(msg.Blob))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %s", err)
		}
		keys = append(keys, key)
		p = msg.Rest
	}
	return keys, nil
}

func findKnown(signers []ssh.Signer, key ssh.PublicKey) ssh.Signer {
	wire := key.Marshal()
	for _, s := range signers {
		if bytes.Equal(s.PublicKey().Marshal(), wire) {
			return s
		}
	}
	return nil
}

type hostKeysProveMsg struct {
	RequestType string
	SessionID   []byte
	Key         []byte
}

func signHostKey(signer ssh.Signer, key ssh.PublicKey, sessionID []byte) (*ssh.Signature, error) {
	msg := hostKeysProveMsg{
		RequestType: requestTypeHostKeysProve,
		SessionID:   sessionID,
		Key:         key.Marshal(),
	}
	return signer.Sign(rand.Reader, ssh.Marshal(msg))
}
