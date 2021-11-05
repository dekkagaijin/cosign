// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/sigstore/cosign/pkg/oci"
)

type VerifyRequest struct {
	SignedEntity oci.SignedEntity
	ToVerify     []oci.Signature

	Extra map[string]interface{}
}

type VerifyResponse struct {
	Sig           oci.Signature
	WithPublicKey crypto.PublicKey

	Cert *x509.Certificate

	Extra map[string]interface{}
}

type VerificationChain struct {
	links []VerificationLink
}

type VerificationLink interface {
	Execute(context.Context, *VerifyRequest, VerificationChain, *VerifyResponse) error
}

func (c VerificationChain) ExecuteNext(ctx context.Context, req *VerifyRequest, resp *VerifyResponse) error {
	if len(c.links) == 0 {
		return nil
	}
	link := c.links[0]
	c.links = c.links[1:]
	return link.Execute(ctx, req, c, resp)
}

func (c VerificationChain) Append(link VerificationLink) VerificationChain {
	c.links = append(c.links, link)
	return c
}

func (c VerificationChain) Prepend(link VerificationLink) VerificationChain {
	tail := c.links
	c.links = make([]VerificationLink, 0, len(tail)+1)
	c.links = append(c.links, link)
	c.links = append(c.links, tail...)
	return c
}

func NewVerificationChain() VerificationChain {
	return VerificationChain{}
}

type appendAttestations struct{}

func (appendAttestations) Execute(ctx context.Context, req *VerifyRequest, c VerificationChain, resp *VerifyResponse) error {
	// TODO(jake): extract the envelope?
	att, err := req.SignedEntity.Attestations()
	if err != nil {
		return err
	}
	sigs, err := att.Get()
	if err != nil {
		return err
	}
	req.ToVerify = append(req.ToVerify, sigs...)
	return c.ExecuteNext(ctx, req, resp)
}

func AppendAttestationsToRequest() VerificationLink {
	return appendAttestations{}
}

type appendSignatures struct{}

func (appendSignatures) Execute(ctx context.Context, req *VerifyRequest, c VerificationChain, resp *VerifyResponse) error {
	att, err := req.SignedEntity.Signatures()
	if err != nil {
		return err
	}
	sigs, err := att.Get()
	if err != nil {
		return err
	}
	req.ToVerify = append(req.ToVerify, sigs...)
	return c.ExecuteNext(ctx, req, resp)
}

func AppendSignaturesToRequest() VerificationLink {
	return appendSignatures{}
}

// type verifySignatures struct {
// 	verifier   signature.Verifier
// 	verifyOpts []signature.VerifyOption
// 	pkOpts     []signature.PublicKeyOption
// }

// func (v verifySignatures) Execute(ctx context.Context, req *VerifyRequest, c VerificationChain, resp *VerifyResponse) error {
// 	for _, sig := range req.ToVerify {
// 		b64sig, err := sig.Base64Signature()
// 		if err != nil {
// 			return err
// 		}
// 		payload, err := sig.Payload()
// 		if err != nil {
// 			return err
// 		}
// 		cert, err := sig.Cert()
// 		if err != nil {
// 			return err
// 		}

// 		switch {
// 			// We have a public key to check against.
// 			case v.verifier != nil:
// 				signature, err := base64.StdEncoding.DecodeString(b64sig)
// 				if err != nil {
// 					return err
// 				}

// 				// The fact that there's no signature (or empty rather), implies
// 				// that this is an Attestation that we're verifying. So, we need
// 				// to construct a Verifier that grabs the signature from the
// 				// payload instead of the Signatures annotations.
// 				if len(signature) == 0 {
// 					co.SigVerifier = newReverseDSSEVerifier(co.SigVerifier)
// 				}
// 				if err := co.SigVerifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx)); err != nil {
// 					return err
// 				}
// 			// If we don't have a public key to check against, we can try a root cert.
// 			case co.RootCerts != nil:
// 				// There might be signatures with a public key instead of a cert, though
// 				if cert == nil {
// 					return errors.New("no certificate found on signature")
// 				}
// 				var pub signature.Verifier
// 				pub, err = signature.LoadECDSAVerifier(cert.PublicKey.(*ecdsa.PublicKey), crypto.SHA256)
// 				if err != nil {
// 					return errors.Wrap(err, "invalid certificate found on signature")
// 				}
// 				// Now verify the cert, then the signature.
// 				if err := TrustedCert(cert, co.RootCerts); err != nil {
// 					return err
// 				}

// 				signature, err := base64.StdEncoding.DecodeString(b64sig)
// 				if err != nil {
// 					return err
// 				}

// 				// The fact that there's no signature (or empty rather), implies
// 				// that this is an Attestation that we're verifying. So, we need
// 				// to construct a Verifier that grabs the signature from the
// 				// payload instead of the Signatures annotations.
// 				if len(signature) == 0 {
// 					pub = newReverseDSSEVerifier(pub)
// 				}

// 				if err := pub.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx)); err != nil {
// 					return err
// 				}
// 				if co.CertEmail != "" {
// 					emailVerified := false
// 					for _, em := range cert.EmailAddresses {
// 						if co.CertEmail == em {
// 							emailVerified = true
// 							break
// 						}
// 					}
// 					if !emailVerified {
// 						return errors.New("expected email not found in certificate")
// 					}
// 				}
// 			}

// 			// We can't check annotations without claims, both require unmarshalling the payload.
// 			if co.ClaimVerifier != nil {
// 				if err := co.ClaimVerifier(sig, h, co.Annotations); err != nil {
// 					return err
// 				}
// 			}

// 			verified, err := VerifyBundle(sig)
// 			if err != nil && co.RekorURL == "" {
// 				return errors.Wrap(err, "unable to verify bundle")
// 			}
// 			bundleVerified = bundleVerified || verified

// 			if !verified && co.RekorURL != "" {
// 				// Get the right public key to use (key or cert)
// 				var pemBytes []byte
// 				if co.SigVerifier != nil {
// 					var pub crypto.PublicKey
// 					pub, err = co.SigVerifier.PublicKey(co.PKOpts...)
// 					if err != nil {
// 						return err
// 					}
// 					pemBytes, err = cryptoutils.MarshalPublicKeyToPEM(pub)
// 				} else {
// 					pemBytes, err = cryptoutils.MarshalCertificateToPEM(cert)
// 				}
// 				if err != nil {
// 					return err
// 				}

// 				// Find the uuid then the entry.
// 				uuid, _, err := FindTlogEntry(rekorClient, b64sig, payload, pemBytes)
// 				if err != nil {
// 					return err
// 				}

// 				// if we have a cert, we should check expiry
// 				// The IntegratedTime verified in VerifyTlog
// 				if cert != nil {
// 					e, err := getTlogEntry(rekorClient, uuid)
// 					if err != nil {
// 						return err
// 					}

// 					// Expiry check is only enabled with Tlog support
// 					if err := checkExpiry(cert, time.Unix(*e.IntegratedTime, 0)); err != nil {
// 						return err
// 					}
// 				}
// 			}
// 			return nil
// 	}
// 	return c.ExecuteNext(ctx, req, resp)
// }

// func VerifySignatures(verifier signature.Verifier, verifyOpts []signature.VerifyOption, pkOpts []signature.PublicKeyOption) VerificationLink {
// 	return appendSignatures{
// 		verifier:   verifier,
// 		verifyOpts: verifyOpts,
// 		pkOpts:     pkOpts,
// 	}
// }
