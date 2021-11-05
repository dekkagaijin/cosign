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
	"errors"

	"github.com/sigstore/cosign/pkg/internal/cosign/verify"
	"github.com/sigstore/cosign/pkg/oci"
)

// type VerifyResult struct {
// 	[]
// }

func VerifyImageSignatures(ctx context.Context, unverified oci.SignedEntity, verifier verify.OCISignatureVerifier) error {
	uvSigs, err := unverified.Signatures()
	if err != nil {
		return err
	}
	sigs, err := uvSigs.Get()
	if err != nil {
		return err
	}
	for _, sig := range sigs {
		if err := verifier.VerifyOCISignature(ctx, sig); err == nil {
			return nil
		}
	}
	return errors.New("could not be verified")
}

func VerifyImageAttestations(ctx context.Context, unverified oci.SignedEntity, verifier verify.OCISignatureVerifier) error {
	uvAtts, err := unverified.Signatures()
	if err != nil {
		return err
	}
	sigs, err := uvAtts.Get()
	if err != nil {
		return err
	}
	for _, sig := range sigs {
		if err := verifier.VerifyOCISignature(ctx, sig); err == nil {
			return nil
		}
	}
	return errors.New("could not be verified")
}
