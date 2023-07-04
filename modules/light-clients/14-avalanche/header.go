package avalanche

import (
	time "time"

	"github.com/cosmos/ibc-go/v7/modules/core/exported"
)

var _ exported.ClientMessage = &Header{}

// ClientType defines that the Header is a Tendermint consensus algorithm
func (h Header) ClientType() string {
	return exported.Avalanche
}

func (h Header) GetHeight() exported.Height {
	//TODO Implement me
	panic("implement me")
	// revision := clienttypes.ParseChainID(h.Header.ChainID)
	// return clienttypes.NewHeight(revision, uint64(h.Header.Height))
}

func (h Header) ValidateBasic() error {
	return nil
}

func (h Header) GetTime() time.Time {
	//TODO Implement me
	panic("implement me")
	// return h.Header.Time
}
