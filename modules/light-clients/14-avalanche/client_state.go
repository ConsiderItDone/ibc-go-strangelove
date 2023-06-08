package avalanche

import (
	"strings"
	"time"

	errorsmod "cosmossdk.io/errors"
	"github.com/cometbft/cometbft/light"
	tmtypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"

	"github.com/cosmos/ibc-go/v7/modules/core/exported"
)

var _ exported.ClientState = (*ClientState)(nil)

func (m *ClientState) ClientType() string {
	return exported.Avalanche
}

func (m *ClientState) GetLatestHeight() exported.Height {
	return m.LatestHeight
}

func (m *ClientState) Validate() error {
	if strings.TrimSpace(m.ChainId) == "" {
		return errorsmod.Wrap(ErrInvalidChainID, "chain id cannot be empty string")
	}

	// NOTE: the value of tmtypes.MaxChainIDLen may change in the future.
	// If this occurs, the code here must account for potential difference
	// between the tendermint version being run by the counterparty chain
	// and the tendermint version used by this light client.
	// https://github.com/cosmos/ibc-go/issues/177
	if len(m.ChainId) > tmtypes.MaxChainIDLen {
		return errorsmod.Wrapf(ErrInvalidChainID, "chainID is too long; got: %d, max: %d", len(m.ChainId), tmtypes.MaxChainIDLen)
	}

	if err := light.ValidateTrustLevel(m.TrustLevel.ToTendermint()); err != nil {
		return err
	}
	if m.TrustingPeriod <= 0 {
		return errorsmod.Wrap(ErrInvalidTrustingPeriod, "trusting period must be greater than zero")
	}
	if m.UnbondingPeriod <= 0 {
		return errorsmod.Wrap(ErrInvalidUnbondingPeriod, "unbonding period must be greater than zero")
	}
	if m.MaxClockDrift <= 0 {
		return errorsmod.Wrap(ErrInvalidMaxClockDrift, "max clock drift must be greater than zero")
	}

	// the latest height revision number must match the chain id revision number
	if m.LatestHeight.RevisionNumber != clienttypes.ParseChainID(m.ChainId) {
		return errorsmod.Wrapf(ErrInvalidHeaderHeight,
			"latest height revision number must match chain id revision number (%d != %d)", m.LatestHeight.RevisionNumber, clienttypes.ParseChainID(m.ChainId))
	}
	if m.LatestHeight.RevisionHeight == 0 {
		return errorsmod.Wrapf(ErrInvalidHeaderHeight, "tendermint client's latest height revision height cannot be zero")
	}
	if m.TrustingPeriod >= m.UnbondingPeriod {
		return errorsmod.Wrapf(
			ErrInvalidTrustingPeriod,
			"trusting period (%s) should be < unbonding period (%s)", m.TrustingPeriod, m.UnbondingPeriod,
		)
	}

	if m.ProofSpecs == nil {
		return errorsmod.Wrap(ErrInvalidProofSpecs, "proof specs cannot be nil for tm client")
	}
	for i, spec := range m.ProofSpecs {
		if spec == nil {
			return errorsmod.Wrapf(ErrInvalidProofSpecs, "proof spec cannot be nil at index: %d", i)
		}
	}
	// UpgradePath may be empty, but if it isn't, each key must be non-empty
	for i, k := range m.UpgradePath {
		if strings.TrimSpace(k) == "" {
			return errorsmod.Wrapf(clienttypes.ErrInvalidClient, "key in upgrade path at index %d cannot be empty", i)
		}
	}

	return nil
}

func (m *ClientState) Status(ctx sdk.Context, clientStore sdk.KVStore, cdc codec.BinaryCodec) exported.Status {
	if !m.FrozenHeight.IsZero() {
		return exported.Frozen
	}

	// get latest consensus state from clientStore to check for expiry
	consState, found := GetConsensusState(clientStore, cdc, m.GetLatestHeight())
	if !found {
		// if the client state does not have an associated consensus state for its latest height
		// then it must be expired
		return exported.Expired
	}

	if m.IsExpired(consState.Timestamp, ctx.BlockTime()) {
		return exported.Expired
	}

	return exported.Active
}

// IsExpired returns whether or not the client has passed the trusting period since the last
// update (in which case no headers are considered valid).
func (m *ClientState) IsExpired(latestTimestamp, now time.Time) bool {
	expirationTime := latestTimestamp.Add(m.TrustingPeriod)
	return !expirationTime.After(now)
}


func (m *ClientState) ZeroCustomFields() exported.ClientState {
	// copy over all chain-specified fields
	// and leave custom fields empty
	return &ClientState{
		ChainId:         m.ChainId,
		UnbondingPeriod: m.UnbondingPeriod,
		LatestHeight:    m.LatestHeight,
		ProofSpecs:      m.ProofSpecs,
		UpgradePath:     m.UpgradePath,
	}
}

func (m *ClientState) GetTimestampAtHeight(ctx sdk.Context, clientStore sdk.KVStore, cdc codec.BinaryCodec, height exported.Height) (uint64, error) {
	// get consensus state at height from clientStore to check for expiry
	consState, found := GetConsensusState(clientStore, cdc, height)
	if !found {
		return 0, errorsmod.Wrapf(clienttypes.ErrConsensusStateNotFound, "height (%s)", height)
	}
	return consState.GetTimestamp(), nil
}

func (m *ClientState) Initialize(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, consState exported.ConsensusState) error {
	consensusState, ok := consState.(*ConsensusState)
	if !ok {
		return errorsmod.Wrapf(clienttypes.ErrInvalidConsensus, "invalid initial consensus state. expected type: %T, got: %T",
			&ConsensusState{}, consState)
	}

	setClientState(clientStore, cdc, m)
	setConsensusState(clientStore, cdc, consensusState, m.GetLatestHeight())
	setConsensusMetadata(ctx, clientStore, m.GetLatestHeight())

	return nil
}

func (m *ClientState) VerifyMembership(ctx sdk.Context, clientStore sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, proof []byte, path exported.Path, value []byte) error {
	//TODO implement me
	panic("implement me")
}

func (m *ClientState) VerifyNonMembership(ctx sdk.Context, clientStore sdk.KVStore, cdc codec.BinaryCodec, height exported.Height, delayTimePeriod uint64, delayBlockPeriod uint64, proof []byte, path exported.Path) error {
	//TODO implement me
	panic("implement me")
}

func (m *ClientState) VerifyClientMessage(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, clientMsg exported.ClientMessage) error {
	//TODO implement me
	panic("implement me")
}

func (m *ClientState) CheckForMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, clientMsg exported.ClientMessage) bool {
	//TODO implement me
	panic("implement me")
}

func (m *ClientState) UpdateStateOnMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, clientMsg exported.ClientMessage) {
	//TODO implement me
	panic("implement me")
}

func (m *ClientState) UpdateState(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, clientMsg exported.ClientMessage) []exported.Height {
	//TODO implement me
	panic("implement me")
}

func (m *ClientState) CheckSubstituteAndUpdateState(ctx sdk.Context, cdc codec.BinaryCodec, subjectClientStore, substituteClientStore sdk.KVStore, substituteClient exported.ClientState) error {
	//TODO implement me
	panic("implement me")
}

func (m *ClientState) VerifyUpgradeAndUpdateState(ctx sdk.Context, cdc codec.BinaryCodec, store sdk.KVStore, newClient exported.ClientState, newConsState exported.ConsensusState, proofUpgradeClient, proofUpgradeConsState []byte) error {
	//TODO implement me
	panic("implement me")
}
