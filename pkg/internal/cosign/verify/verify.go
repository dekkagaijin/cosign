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

package verify

import (
	"bytes"
	"context"
	"encoding/base64"

	"github.com/sigstore/cosign/pkg/oci"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

type OCISignatureVerifier interface {
	VerifyOCISignature(context.Context, oci.Signature) error
}

type SimpleImageSignatureVerifier struct {
	SigVerifier signature.Verifier
}

func (v *SimpleImageSignatureVerifier) VerifyOCISignature(ctx context.Context, unverified oci.Signature) error {
	b64Sig, err := unverified.Base64Signature()
	if err != nil {
		return err
	}
	payload, err := unverified.Payload()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return err
	}
	return v.SigVerifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx))
}

type AttestationVerifier struct {
	SigVerifier signature.Verifier
}

func (v *AttestationVerifier) VerifyOCISignature(ctx context.Context, unverified oci.Signature) error {
	b64Sig, err := unverified.Base64Signature()
	if err != nil {
		return err
	}
	payload, err := unverified.Payload()
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return err
	}
	return v.SigVerifier.VerifySignature(bytes.NewReader(signature), bytes.NewReader(payload), options.WithContext(ctx))
}
