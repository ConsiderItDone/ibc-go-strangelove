package avalanche

import (
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
	return nil
}
