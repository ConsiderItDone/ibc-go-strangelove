package avalanche

import (
	errorsmod "cosmossdk.io/errors"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
)

var _ exported.ClientMessage = &Header{}

// ConsensusState returns the updated consensus state associated with the header
func (h Header) ConsensusState() *ConsensusState {
	return &ConsensusState{
		Timestamp:          h.SubnetHeader.Timestamp,
		StorageRoot:        h.StorageRoot,
		SignedStorageRoot:  h.SignedStorageRoot,
		ValidatorSet:       h.ValidatorSet,
		SignedValidatorSet: h.SignedValidatorSet,
		Vdrs:               h.Vdrs,
		SignersInput:       h.SignersInput,
	}
}

// ClientType defines that the Header is a Tendermint consensus algorithm
func (h Header) ClientType() string {
	return exported.Avalanche
}

func (h Header) ValidateBasic() error {

	if len(h.Vdrs) == 0 {
		return errorsmod.Wrap(clienttypes.ErrInvalidHeader, "Avalanche header cannot empty validators set")
	}

	return nil
}
