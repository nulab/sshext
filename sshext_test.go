package sshext

import (
	"crypto/rand"
	"golang.org/x/crypto/ssh"
	"reflect"
	"testing"
)

const (
	privateKeyRSA = `-----BEGIN OPENSSH PRIVATE KEY-----
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
KbA/9qeRwtPwr5AAAAAAEC
-----END OPENSSH PRIVATE KEY-----`
	privateKeyECDSA256 = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSwaFQWJD0U0h7Oh+ToLJOYkiRqYIHP
I5ilFGKGpSEr6KziaOMCDisL/wQ7hzrxyMgLpcpMhYPOFgeqCctUlB3EAAAAmHrf0vR639
L0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLBoVBYkPRTSHs6H
5Ogsk5iSJGpggc8jmKUUYoalISvorOJo4wIOKwv/BDuHOvHIyAulykyFg84WB6oJy1SUHc
QAAAAgRRmXsLdGN6rQZGo3jIWDpfOLCgx4XWDn32amdkcn37MAAAAA
-----END OPENSSH PRIVATE KEY-----`
	privateKeyED25519 = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCXUsZbbOVZ3JCWlqnPQg49UPZ8o9vGrUl2bTG4hXmV7QAAAIj07eBb9O3g
WwAAAAtzc2gtZWQyNTUxOQAAACCXUsZbbOVZ3JCWlqnPQg49UPZ8o9vGrUl2bTG4hXmV7Q
AAAEDWCtVz/whCNAG3WNkPuiF5sqQOj0XxWWOtJUsfmRMt4pdSxlts5VnckJaWqc9CDj1Q
9nyj28atSXZtMbiFeZXtAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`
)

var (
	singerRSA, _           = ssh.ParsePrivateKey([]byte(privateKeyRSA))
	singerECDSA256, _      = ssh.ParsePrivateKey([]byte(privateKeyECDSA256))
	singerED25519, _       = ssh.ParsePrivateKey([]byte(privateKeyED25519))
	hostKeyPayloadRSA      = ssh.Marshal(struct{ string }{string(singerRSA.PublicKey().Marshal())})
	hostKeyPayloadECDSA256 = ssh.Marshal(struct{ string }{string(singerECDSA256.PublicKey().Marshal())})
	hostKeyPayloadED25519  = ssh.Marshal(struct{ string }{string(singerED25519.PublicKey().Marshal())})
	signatureRSA, _        = singerRSA.Sign(rand.Reader, ssh.Marshal(hostKeysProveMsg{
		RequestType: requestTypeHostKeysProve,
		SessionID:   []byte("foo"),
		Key:         singerRSA.PublicKey().Marshal(),
	}))
	signatureECDSA256, _ = singerECDSA256.Sign(rand.Reader, ssh.Marshal(hostKeysProveMsg{
		RequestType: requestTypeHostKeysProve,
		SessionID:   []byte("foo"),
		Key:         singerRSA.PublicKey().Marshal(),
	}))
	signatureED25519, _ = singerED25519.Sign(rand.Reader, ssh.Marshal(hostKeysProveMsg{
		RequestType: requestTypeHostKeysProve,
		SessionID:   []byte("foo"),
		Key:         singerRSA.PublicKey().Marshal(),
	}))
	signaturePayloadRSA      = ssh.Marshal(struct{ string }{string(ssh.Marshal(signatureRSA))})
	signaturePayloadECDSA256 = ssh.Marshal(struct{ string }{string(ssh.Marshal(signatureECDSA256))})
	signaturePayloadED25519  = ssh.Marshal(struct{ string }{string(ssh.Marshal(signatureED25519))})
)

func Test_marshalPublicKeys(t *testing.T) {
	type args struct {
		signers []ssh.Signer
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "rsa",
			args: args{
				signers: []ssh.Signer{singerRSA},
			},
			want: hostKeyPayloadRSA,
		},
		{
			name: "ecdsa-256",
			args: args{
				signers: []ssh.Signer{singerECDSA256},
			},
			want: hostKeyPayloadECDSA256,
		},
		{
			name: "ed25519",
			args: args{
				signers: []ssh.Signer{singerED25519},
			},
			want: hostKeyPayloadED25519,
		},
		{
			name: "rsa and ecdsa-256 and ed25519",
			args: args{
				signers: []ssh.Signer{singerRSA, singerECDSA256, singerED25519},
			},
			want: func() []byte {
				var p []byte
				p = append(p, hostKeyPayloadRSA...)
				p = append(p, hostKeyPayloadECDSA256...)
				p = append(p, hostKeyPayloadED25519...)
				return p
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := marshalPublicKeys(tt.args.signers); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("marshalPublicKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parsePublicKeys(t *testing.T) {
	type args struct {
		p []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []ssh.PublicKey
		wantErr bool
	}{
		{
			name: "rsa",
			args: args{
				p: hostKeyPayloadRSA,
			},
			want:    []ssh.PublicKey{singerRSA.PublicKey()},
			wantErr: false,
		},
		{
			name: "ecdsa-256",
			args: args{
				p: hostKeyPayloadECDSA256,
			},
			want:    []ssh.PublicKey{singerECDSA256.PublicKey()},
			wantErr: false,
		},
		{
			name: "ed25519",
			args: args{
				p: hostKeyPayloadED25519,
			},
			want:    []ssh.PublicKey{singerED25519.PublicKey()},
			wantErr: false,
		},
		{
			name: "rsa and ecdsa-256 and ed25519",
			args: args{
				p: func() []byte {
					var p []byte
					p = append(p, hostKeyPayloadRSA...)
					p = append(p, hostKeyPayloadECDSA256...)
					p = append(p, hostKeyPayloadED25519...)
					return p
				}(),
			},
			want:    []ssh.PublicKey{singerRSA.PublicKey(), singerECDSA256.PublicKey(), singerED25519.PublicKey()},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePublicKeys(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePublicKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePublicKeys() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_findKnown(t *testing.T) {
	type args struct {
		signers []ssh.Signer
		key     ssh.PublicKey
	}
	tests := []struct {
		name string
		args args
		want ssh.Signer
	}{
		{
			name: "rsa",
			args: args{
				signers: []ssh.Signer{singerRSA, singerECDSA256, singerED25519},
				key:     singerRSA.PublicKey(),
			},
			want: singerRSA,
		},
		{
			name: "ecdsa-256",
			args: args{
				signers: []ssh.Signer{singerRSA, singerECDSA256, singerED25519},
				key:     singerECDSA256.PublicKey(),
			},
			want: singerECDSA256,
		},
		{
			name: "ed25519",
			args: args{
				signers: []ssh.Signer{singerRSA, singerECDSA256, singerED25519},
				key:     singerED25519.PublicKey(),
			},
			want: singerED25519,
		},
		{
			name: "unknown",
			args: args{
				signers: []ssh.Signer{singerRSA, singerECDSA256},
				key:     singerED25519.PublicKey(),
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findKnown(tt.args.signers, tt.args.key); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findKnown() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_marshalSignatures(t *testing.T) {
	type args struct {
		signatures []*ssh.Signature
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "rsa",
			args: args{
				signatures: []*ssh.Signature{signatureRSA},
			},
			want: signaturePayloadRSA,
		},
		{
			name: "ecdsa-256",
			args: args{
				signatures: []*ssh.Signature{signatureECDSA256},
			},
			want: signaturePayloadECDSA256,
		},
		{
			name: "ed25519",
			args: args{
				signatures: []*ssh.Signature{signatureED25519},
			},
			want: signaturePayloadED25519,
		},
		{
			name: "rsa and ecdsa-256 and ed25519",
			args: args{
				signatures: []*ssh.Signature{signatureRSA, signatureECDSA256, signatureED25519},
			},
			want: func() []byte {
				var p []byte
				p = append(p, signaturePayloadRSA...)
				p = append(p, signaturePayloadECDSA256...)
				p = append(p, signaturePayloadED25519...)
				return p
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := marshalSignatures(tt.args.signatures); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("marshalSignatures() = %v, want %v", got, tt.want)
			}
		})
	}
}
