package avalanche

import (
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
)

var _ exported.ClientMessage = &Header{}

// ClientType defines that the Header is a Tendermint consensus algorithm
func (h Header) ClientType() string {
	return exported.Avalanche
}

// ValidateBasic calls the SignedHeader ValidateBasic function and checks
// that validatorsets are not nil.
// NOTE: TrustedHeight and TrustedValidators may be empty when creating client
// with MsgCreateClient
func (h Header) ValidateBasic() error {
	return nil
}
