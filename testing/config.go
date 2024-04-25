package ibctesting

import (
	"time"

	connectiontypes "github.com/cosmos/ibc-go/v8/modules/core/03-connection/types"
	channeltypes "github.com/cosmos/ibc-go/v8/modules/core/04-channel/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	ibctm "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	ibcava "github.com/cosmos/ibc-go/v8/modules/light-clients/14-avalanche"
	"github.com/cosmos/ibc-go/v8/testing/mock"
)

type ClientConfig interface {
	GetClientType() string
}

type TendermintConfig struct {
	TrustLevel      ibctm.Fraction
	TrustingPeriod  time.Duration
	UnbondingPeriod time.Duration
	MaxClockDrift   time.Duration
}

func NewTendermintConfig() *TendermintConfig {
	return &TendermintConfig{
		TrustLevel:      DefaultTrustLevel,
		TrustingPeriod:  TrustingPeriod,
		UnbondingPeriod: UnbondingPeriod,
		MaxClockDrift:   MaxClockDrift,
	}
}

func (*TendermintConfig) GetClientType() string {
	return exported.Tendermint
}

type AvalancheConfig struct {
	TrustLevel      ibcava.Fraction
	TrustingPeriod  time.Duration
}

func NewAvalancheConfig() *AvalancheConfig {
	return &AvalancheConfig{
		TrustLevel:      ibcava.DefaultTrustLevel,
		TrustingPeriod:  TrustingPeriod,
	}
}

func (avacfg *AvalancheConfig) GetClientType() string {
	return exported.Avalanche
}

type ConnectionConfig struct {
	DelayPeriod uint64
	Version     *connectiontypes.Version
}

func NewConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		DelayPeriod: DefaultDelayPeriod,
		Version:     ConnectionVersion,
	}
}

type ChannelConfig struct {
	PortID  string
	Version string
	Order   channeltypes.Order
}

func NewChannelConfig() *ChannelConfig {
	return &ChannelConfig{
		PortID:  mock.PortID,
		Version: DefaultChannelVersion,
		Order:   channeltypes.UNORDERED,
	}
}
