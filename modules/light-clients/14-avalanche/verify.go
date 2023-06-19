package avalanche

import (
	fmt "fmt"

	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

func Verify(
	signersInput []byte,
	signature [bls.SignatureLen]byte,
	data []byte,
	vdrs []*warp.Validator,
	totalWeight uint64,
	pChainHeight uint64,
	quorumNum uint64,
	quorumDen uint64,
) error {
	// Parse signer bit vector
	//
	// We assert that the length of [signerIndices.Bytes()] is equal
	// to [len(s.Signers)] to ensure that [s.Signers] does not have
	// any unnecessary zero-padding to represent the [set.Bits].
	signerIndices := set.BitsFromBytes(signersInput)
	if len(signerIndices.Bytes()) != len(signersInput) {
		return fmt.Errorf("bitset is invalid")
	}

	// Get the validators that (allegedly) signed the message.
	signers, err := warp.FilterValidators(signerIndices, vdrs)
	if err != nil {
		return err
	}

	// Because [signers] is a subset of [vdrs], this can never error.
	sigWeight, _ := warp.SumWeight(signers)

	// Make sure the signature's weight is sufficient.
	err = warp.VerifyWeight(
		sigWeight,
		totalWeight,
		quorumNum,
		quorumDen,
	)
	if err != nil {
		return err
	}

	// Parse the aggregate signature
	aggSig, err := bls.SignatureFromBytes(signature[:])
	if err != nil {
		return fmt.Errorf("failed to parse signature: %v", err)
	}

	// Create the aggregate public key
	aggPubKey, err := warp.AggregatePublicKeys(signers)
	if err != nil {
		return err
	}

	if !bls.Verify(aggPubKey, aggSig, data) {
		return fmt.Errorf("signature is invalid")
	}
	return nil
}
