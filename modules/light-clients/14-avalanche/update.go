package avalanche

import (
	errorsmod "cosmossdk.io/errors"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
)

// VerifyClientMessage checks if the clientMessage is of type Header or Misbehaviour and verifies the message
func (cs *ClientState) VerifyClientMessage(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore,
	clientMsg exported.ClientMessage,
) error {
	switch msg := clientMsg.(type) {
	case *Header:
		return cs.verifyHeader(ctx, clientStore, cdc, msg)
	case *Misbehaviour:
		return cs.verifyMisbehaviour(ctx, clientStore, cdc, msg)
	default:
		return clienttypes.ErrInvalidClientType
	}
}

// verifyHeader returns an error if:
// - the client or header provided are not parseable to tendermint types
// - the header is invalid
// - header height is less than or equal to the trusted header height
// - header revision is not equal to trusted header revision
// - header valset commit verification fails
// - header timestamp is past the trusting period in relation to the consensus state
// - header timestamp is less than or equal to the consensus state timestamp
func (cs *ClientState) verifyHeader(
	ctx sdk.Context, clientStore sdk.KVStore, cdc codec.BinaryCodec,
	header *Header,
) error {
	// Retrieve trusted consensus states for each Header in misbehaviour
	consState, found := GetConsensusState(clientStore, cdc, header.SubnetTrustedHeight)
	if !found {
		return errorsmod.Wrapf(clienttypes.ErrConsensusStateNotFound, "could not get trusted consensus state from clientStore for Header at TrustedHeight: %s", header.SubnetTrustedHeight)
	}

	// UpdateClient only accepts updates with a header at the same revision
	// as the trusted consensus state
	if header.SubnetHeader.Height.RevisionNumber != header.SubnetTrustedHeight.RevisionNumber {
		return errorsmod.Wrapf(
			ErrInvalidHeaderHeight,
			"header height revision %d does not match trusted header revision %d",
			header.SubnetHeader.Height.RevisionNumber, header.SubnetTrustedHeight.RevisionNumber,
		)
	}

	if header.PchainHeader.Height.RevisionNumber != header.PchainTrustedHeight.RevisionNumber {
		return errorsmod.Wrapf(
			ErrInvalidHeaderHeight,
			"header height revision %d does not match trusted header revision %d",
			header.PchainHeader.Height.RevisionNumber, header.PchainTrustedHeight.RevisionNumber,
		)
	}
	// assert header height is newer than consensus state
	if header.PchainHeader.Height.LTE(header.PchainTrustedHeight) {
		return errorsmod.Wrapf(
			clienttypes.ErrInvalidHeader,
			"header height ≤ consensus state height (%s ≤ %s)", header.PchainHeader.Height, header.PchainTrustedHeight,
		)
	}

	headerUniqVdrs, headerTotalWeight, err := ValidateValidatorSet(ctx, header.Vdrs)
	if err != nil {
		return errorsmod.Wrap(err, "failed to verify header")
	}
	consensusUniqVdrs, consensusTotalWeight, err := ValidateValidatorSet(ctx, consState.Vdrs)
	if err != nil {
		return errorsmod.Wrap(err, "failed to verify header")
	}
	if headerTotalWeight != consensusTotalWeight {
		return errorsmod.Wrap(err, "failed to verify header")
	}

	if len(headerUniqVdrs) != len(consensusUniqVdrs) {
		return errorsmod.Wrap(err, "failed to verify header")
	}
	for i := range headerUniqVdrs {
		if headerUniqVdrs[i] != consensusUniqVdrs[i] {
			return errorsmod.Wrap(err, "failed to verify header")
		}
	}
	return nil
}
