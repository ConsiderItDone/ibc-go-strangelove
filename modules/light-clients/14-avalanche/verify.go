package avalanche

import (
	fmt "fmt"

	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/math"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
)

func Verify(
	signersInput []byte, // header
	signature [bls.SignatureLen]byte, //  (1 - signed_storage_root; 2 - signed_validator_set)
	data []byte, // payload (1 - storage root; 2 - validater set)
	vdrs []*warp.Validator, // header
	totalWeight uint64, // header
	quorumNum uint64, // cs
	quorumDen uint64, // cs
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

func ValidateValidatorSet(
	vdrSet []*Validator,
) ([]*warp.Validator, uint64, error) {
	var (
		vdrs        = make([]*warp.Validator, len(vdrSet))
		totalWeight uint64
		err         error
	)
	for _, vdr := range vdrSet {
		totalWeight, err = math.Add64(totalWeight, vdr.Weight)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %v", warp.ErrWeightOverflow, err)
		}

		if vdr.PublicKeyByte == nil {
			continue
		}

		publicKey, err := bls.PublicKeyFromBytes(vdr.PublicKeyByte)
		if err != nil {
			return nil, 0, err
		}

		warpVdr := &warp.Validator{
			PublicKey:      publicKey,
			PublicKeyBytes: vdr.PublicKeyByte,
			Weight:         vdr.Weight,
			NodeIDs:        SetNodeIDs(vdr.NodeIDs),
		}
		vdrs = append(vdrs, warpVdr)
	}
	utils.Sort(vdrs)
	return vdrs, totalWeight, nil
}

func SetSignature(b []byte) (signature [bls.SignatureLen]byte) {
	if len(b) > len(signature) {
		b = b[len(b)-bls.SignatureLen:]
	}
	copy(signature[bls.SignatureLen-len(b):], b)
	return
}

func SetNodeIDs(data [][]byte) []ids.NodeID {
	var (
		nodeIDs = make([]ids.NodeID, len(data))
	)
	for i, b := range data {
		if len(b) > len(nodeIDs[i]) {
			b = b[len(b)-len(nodeIDs[i]):]
		}
		copy(nodeIDs[i][len(nodeIDs[i])-len(b):], b)
	}
	return nodeIDs
}
