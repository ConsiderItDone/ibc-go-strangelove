package avalanche

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"time"

	errorsmod "cosmossdk.io/errors"
	"github.com/ava-labs/subnet-evm/ethdb"
	"github.com/ava-labs/subnet-evm/ethdb/memorydb"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	ibcerrors "github.com/cosmos/ibc-go/v7/internal/errors"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/v7/modules/core/24-host"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/cosmos/ibc-go/v7/modules/core/exported"
)

var _ exported.ClientState = (*ClientState)(nil)

const (
	// MaxChainIDLen is a maximum length of the chain ID.
	MaxChainIDLen = 50
)

// NewClientState creates a new ClientState instance
func NewClientState(
	chainID string, trustLevel Fraction,
	trustingPeriod time.Duration,
	maxClockDrift time.Duration,
	latestHeight clienttypes.Height,
	upgradePath string,
	proof [][]byte,
) *ClientState {
	return &ClientState{
		ChainId:        chainID,
		TrustLevel:     trustLevel,
		TrustingPeriod: trustingPeriod,
		MaxClockDrift:  maxClockDrift,
		LatestHeight:   latestHeight,
		FrozenHeight:   clienttypes.ZeroHeight(),
		UpgradePath:    upgradePath,
		Proof:          proof,
	}
}

func (cs *ClientState) ClientType() string {
	return exported.Avalanche
}

func (cs *ClientState) GetChainID() string {
	return cs.ChainId
}

func (cs *ClientState) GetLatestHeight() exported.Height {
	return cs.LatestHeight
}

func (cs *ClientState) Validate() error {
	if strings.TrimSpace(cs.ChainId) == "" {
		return errorsmod.Wrap(ErrInvalidChainID, "chain id cannot be empty string")
	}

	if len(cs.ChainId) > MaxChainIDLen {
		return errorsmod.Wrapf(ErrInvalidChainID, "chainID is too long; got: %d, max: %d", len(cs.ChainId), MaxChainIDLen)
	}

	if cs.TrustingPeriod <= 0 {
		return errorsmod.Wrap(ErrInvalidTrustingPeriod, "trusting period must be greater than zero")
	}

	// the latest height revision number must match the chain id revision number
	if cs.LatestHeight.RevisionNumber != clienttypes.ParseChainID(cs.ChainId) {
		return errorsmod.Wrapf(ErrInvalidHeaderHeight,
			"latest height revision number must match chain id revision number (%d != %d)", cs.LatestHeight.RevisionNumber, clienttypes.ParseChainID(cs.ChainId))
	}
	if cs.LatestHeight.RevisionHeight == 0 {
		return errorsmod.Wrapf(ErrInvalidHeaderHeight, "tendermint client's latest height revision height cannot be zero")
	}
	// UpgradePath may be empty, but if it isn't, each key must be non-empty
	for cs.UpgradePath == "" {
		return errorsmod.Wrapf(clienttypes.ErrInvalidClient, "upgrade path cannot be empty")
	}

	return nil
}

func (cs *ClientState) Status(ctx sdk.Context, clientStore sdk.KVStore, cdc codec.BinaryCodec) exported.Status {
	if !cs.FrozenHeight.IsZero() {
		return exported.Frozen
	}

	// get latest consensus state from clientStore to check for expiry
	consState, found := GetConsensusState(clientStore, cdc, cs.GetLatestHeight())
	if !found {
		// if the client state does not have an associated consensus state for its latest height
		// then it must be expired
		return exported.Expired
	}

	if cs.IsExpired(consState.Timestamp, ctx.BlockTime()) {
		return exported.Expired
	}

	return exported.Active
}

// IsExpired returns whether or not the client has passed the trusting period since the last
// update (in which case no headers are considered valid).
func (cs *ClientState) IsExpired(latestTimestamp, now time.Time) bool {
	expirationTime := latestTimestamp.Add(cs.TrustingPeriod)
	return !expirationTime.After(now)
}

func (cs *ClientState) ZeroCustomFields() exported.ClientState {
	// copy over all chain-specified fields
	// and leave custom fields empty
	return &ClientState{
		ChainId:      cs.ChainId,
		LatestHeight: cs.LatestHeight,
		UpgradePath:  cs.UpgradePath,
	}
}

func (cs *ClientState) GetTimestampAtHeight(ctx sdk.Context, clientStore sdk.KVStore, cdc codec.BinaryCodec, height exported.Height) (uint64, error) {
	// get consensus state at height from clientStore to check for expiry
	consState, found := GetConsensusState(clientStore, cdc, height)
	if !found {
		return 0, errorsmod.Wrapf(clienttypes.ErrConsensusStateNotFound, "height (%s)", height)
	}
	return consState.GetTimestamp(), nil
}

func (cs *ClientState) Initialize(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, consState exported.ConsensusState) error {
	consensusState, ok := consState.(*ConsensusState)
	if !ok {
		return errorsmod.Wrapf(clienttypes.ErrInvalidConsensus, "invalid initial consensus state. expected type: %T, got: %T",
			&ConsensusState{}, consState)
	}

	setClientState(clientStore, cdc, cs)
	SetConsensusState(clientStore, cdc, consensusState, cs.GetLatestHeight())

	return nil
}

// verifyDelayPeriodPassed will ensure that at least delayTimePeriod amount of time and delayBlockPeriod number of blocks have passed
// since consensus state was submitted before allowing verification to continue.
func verifyDelayPeriodPassed(ctx sdk.Context, store sdk.KVStore, proofHeight exported.Height, delayTimePeriod, delayBlockPeriod uint64) error {
	if delayTimePeriod != 0 {
		// check that executing chain's timestamp has passed consensusState's processed time + delay time period
		processedTime, ok := GetProcessedTime(store, proofHeight)
		if !ok {
			return errorsmod.Wrapf(ErrProcessedTimeNotFound, "processed time not found for height: %s", proofHeight)
		}

		// TODO
		currentTimestamp := uint64(ctx.BlockTime().UnixNano())
		validTime := processedTime + delayTimePeriod

		// NOTE: delay time period is inclusive, so if currentTimestamp is validTime, then we return no error
		if currentTimestamp < validTime {
			return errorsmod.Wrapf(ErrDelayPeriodNotPassed, "cannot verify packet until time: %d, current time: %d",
				validTime, currentTimestamp)
		}

	}

	if delayBlockPeriod != 0 {
		// check that executing chain's height has passed consensusState's processed height + delay block period
		processedHeight, ok := GetProcessedHeight(store, proofHeight)
		if !ok {
			return errorsmod.Wrapf(ErrProcessedHeightNotFound, "processed height not found for height: %s", proofHeight)
		}

		currentHeight := clienttypes.GetSelfHeight(ctx)
		validHeight := clienttypes.NewHeight(processedHeight.GetRevisionNumber(), processedHeight.GetRevisionHeight()+delayBlockPeriod)

		// NOTE: delay block period is inclusive, so if currentHeight is validHeight, then we return no error
		if currentHeight.LT(validHeight) {
			return errorsmod.Wrapf(ErrDelayPeriodNotPassed, "cannot verify packet until height: %s, current height: %s",
				validHeight, currentHeight)
		}
	}

	return nil
}

func (cs *ClientState) VerifyClientMessage(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, clientMsg exported.ClientMessage) error {
	// switch msg := clientMsg.(type) {
	// case *Header:
	// 	return cs.verifyHeader(ctx, clientStore, cdc, msg)
	// case *Misbehaviour:
	// 	return cs.verifyMisbehaviour(ctx, clientStore, cdc, msg)
	// default:
	// 	return clienttypes.ErrInvalidClientType
	// }
	//TODO implement me
	panic("implement me")
}

func (cs *ClientState) UpdateStateOnMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, clientMsg exported.ClientMessage) {
	cs.FrozenHeight = FrozenHeight

	clientStore.Set(host.ClientStateKey(), clienttypes.MustMarshalClientState(cdc, cs))
}

func (cs *ClientState) UpdateState(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, clientMsg exported.ClientMessage) []exported.Height {
	header, ok := clientMsg.(*Header)
	if !ok {
		panic(fmt.Errorf("expected type %T, got %T", &Header{}, clientMsg))
	}

	cs.pruneOldestConsensusState(ctx, cdc, clientStore)

	// check for duplicate update
	if consensusState, _ := GetConsensusState(clientStore, cdc, header.GetHeight()); consensusState != nil {
		// perform no-op
		return []exported.Height{header.GetHeight()}
	}

	height := header.GetHeight().(clienttypes.Height)
	if height.GT(cs.LatestHeight) {
		cs.LatestHeight = height
	}

	consensusState := &ConsensusState{
		Timestamp:          header.GetTime(),
		StorageRoot:        header.StorageRoot,
		SignedStorageRoot:  header.SignedStorageRoot,
		ValidatorSet:       header.ValidatorSet,
		SignedValidatorSet: header.SignedValidatorSet,
		Vdrs:               header.Vdrs,
		SignersInput:       header.SignersInput,
	}

	// set client state, consensus state and asssociated metadata
	setClientState(clientStore, cdc, cs)
	SetConsensusState(clientStore, cdc, consensusState, header.GetHeight())
	setConsensusMetadata(ctx, clientStore, header.GetHeight())

	return []exported.Height{height}
}

// pruneOldestConsensusState will retrieve the earliest consensus state for this clientID and check if it is expired. If it is,
// that consensus state will be pruned from store along with all associated metadata. This will prevent the client store from
// becoming bloated with expired consensus states that can no longer be used for updates and packet verification.
func (cs ClientState) pruneOldestConsensusState(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore) {
	// Check the earliest consensus state to see if it is expired, if so then set the prune height
	// so that we can delete consensus state and all associated metadata.
	var (
		pruneHeight exported.Height
	)

	pruneCb := func(height exported.Height) bool {
		consState, found := GetConsensusState(clientStore, cdc, height)
		// this error should never occur
		if !found {
			panic(errorsmod.Wrapf(clienttypes.ErrConsensusStateNotFound, "failed to retrieve consensus state at height: %s", height))
		}

		if cs.IsExpired(consState.Timestamp, ctx.BlockTime()) {
			pruneHeight = height
		}

		return true
	}

	IterateConsensusStateAscending(clientStore, pruneCb)

	// if pruneHeight is set, delete consensus state and metadata
	if pruneHeight != nil {
		deleteConsensusState(clientStore, pruneHeight)
		deleteConsensusMetadata(clientStore, pruneHeight)
	}
}

func (cs *ClientState) CheckSubstituteAndUpdateState(ctx sdk.Context, cdc codec.BinaryCodec, subjectClientStore, substituteClientStore sdk.KVStore, substituteClient exported.ClientState) error {
	substituteClientState, ok := substituteClient.(*ClientState)
	if !ok {
		return errorsmod.Wrapf(clienttypes.ErrInvalidClient, "expected type %T, got %T", &ClientState{}, substituteClient)
	}

	if !IsMatchingClientState(*cs, *substituteClientState) {
		return errorsmod.Wrap(clienttypes.ErrInvalidSubstitute, "subject client state does not match substitute client state")
	}

	if cs.Status(ctx, subjectClientStore, cdc) == exported.Frozen {
		// unfreeze the client
		cs.FrozenHeight = clienttypes.ZeroHeight()
	}

	// copy consensus states and processed time from substitute to subject
	// starting from initial height and ending on the latest height (inclusive)
	height := substituteClientState.GetLatestHeight()

	consensusState, found := GetConsensusState(substituteClientStore, cdc, height)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrConsensusStateNotFound, "unable to retrieve latest consensus state for substitute client")
	}

	SetConsensusState(subjectClientStore, cdc, consensusState, height)

	// set metadata stored for the substitute consensus state
	processedHeight, found := GetProcessedHeight(substituteClientStore, height)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrUpdateClientFailed, "unable to retrieve processed height for substitute client latest height")
	}

	processedTime, found := GetProcessedTime(substituteClientStore, height)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrUpdateClientFailed, "unable to retrieve processed time for substitute client latest height")
	}

	setConsensusMetadataWithValues(subjectClientStore, height, processedHeight, processedTime)

	cs.LatestHeight = substituteClientState.LatestHeight
	cs.ChainId = substituteClientState.ChainId

	// set new trusting period based on the substitute client state
	cs.TrustingPeriod = substituteClientState.TrustingPeriod

	// no validation is necessary since the substitute is verified to be Active
	// in 02-client.
	setClientState(subjectClientStore, cdc, cs)

	return nil
}

// IsMatchingClientState returns true if all the client state parameters match
// except for frozen height, latest height, trusting period, chain-id.
func IsMatchingClientState(subject, substitute ClientState) bool {
	// zero out parameters which do not need to match
	subject.LatestHeight = clienttypes.ZeroHeight()
	subject.FrozenHeight = clienttypes.ZeroHeight()
	subject.TrustingPeriod = time.Duration(0)
	substitute.LatestHeight = clienttypes.ZeroHeight()
	substitute.FrozenHeight = clienttypes.ZeroHeight()
	substitute.TrustingPeriod = time.Duration(0)
	subject.ChainId = ""
	substitute.ChainId = ""
	// sets both sets of flags to true as these flags have been DEPRECATED, see ADR-026 for more information
	subject.AllowUpdateAfterExpiry = true
	substitute.AllowUpdateAfterExpiry = true
	subject.AllowUpdateAfterMisbehaviour = true
	substitute.AllowUpdateAfterMisbehaviour = true

	return reflect.DeepEqual(subject, substitute)
}

func (cs *ClientState) VerifyUpgradeAndUpdateState(ctx sdk.Context, cdc codec.BinaryCodec, clientStore sdk.KVStore, upgradedClient exported.ClientState, upgradedConsState exported.ConsensusState, proofUpgradeClient, proofUpgradeConsState []byte) error {
	if len(cs.UpgradePath) == 0 {
		return errorsmod.Wrap(clienttypes.ErrInvalidUpgradeClient, "cannot upgrade client, no upgrade path set")
	}

	// last height of current counterparty chain must be client's latest height
	lastHeight := cs.GetLatestHeight()

	if !upgradedClient.GetLatestHeight().GT(lastHeight) {
		return errorsmod.Wrapf(ibcerrors.ErrInvalidHeight, "upgraded client height %s must be at greater than current client height %s",
			upgradedClient.GetLatestHeight(), lastHeight)
	}

	// upgraded client state and consensus state must be IBC tendermint client state and consensus state
	// this may be modified in the future to upgrade to a new IBC tendermint type
	// counterparty must also commit to the upgraded consensus state at a sub-path under the upgrade path specified
	avaUpgradeClient, ok := upgradedClient.(*ClientState)
	if !ok {
		return errorsmod.Wrapf(clienttypes.ErrInvalidClientType, "upgraded client must be Tendermint client. expected: %T got: %T",
			&ClientState{}, upgradedClient)
	}
	avaUpgradeConsState, ok := upgradedConsState.(*ConsensusState)
	if !ok {
		return errorsmod.Wrapf(clienttypes.ErrInvalidConsensus, "upgraded consensus state must be Tendermint consensus state. expected %T, got: %T",
			&ConsensusState{}, upgradedConsState)
	}

	// Must prove against latest consensus state to ensure we are verifying against latest upgrade plan
	// This verifies that upgrade is intended for the provided revision, since committed client must exist
	// at this consensus state
	consState, found := GetConsensusState(clientStore, cdc, lastHeight)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrConsensusStateNotFound, "could not retrieve consensus state for lastHeight")
	}

	// Verify client proof
	bz, err := cdc.MarshalInterface(upgradedClient.ZeroCustomFields())
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidClient, "could not marshal client state: %v", err)
	}

	var proofClientMerkle ethdb.Database
	// Populate proof when ProofVals are present in the response. Its ok to pass it as nil to the trie.VerifyRangeProof
	// function as it will assert that all the leaves belonging to the specified root are present.
	if len(cs.Proof) > 0 {
		proofClientMerkle = memorydb.New()
		defer proofClientMerkle.Close()
		for _, proofVal := range cs.Proof {
			proofKey := crypto.Keccak256(proofVal)
			if err := proofClientMerkle.Put(proofKey, proofVal); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("client path is invalid")
	}

	keyClientMerkle := MerkleKey{Key: cs.UpgradePath}

	verifyValueClientMerkle, err := trie.VerifyProof(
		common.BytesToHash(consState.StorageRoot),
		[]byte(keyClientMerkle.Key),
		proofClientMerkle,
	)
	if err != nil {
		return err
	}

	if !bytes.Equal(verifyValueClientMerkle, bz) {
		return errorsmod.Wrapf(err, "client state proof failed. Path: %s", keyClientMerkle)
	}

	// Verify consensus state proof
	bz, err = cdc.MarshalInterface(upgradedConsState)
	if err != nil {
		return errorsmod.Wrapf(clienttypes.ErrInvalidConsensus, "could not marshal consensus state: %v", err)
	}

	var proofConsStateMerkle ethdb.Database
	// Populate proof when ProofVals are present in the response. Its ok to pass it as nil to the trie.VerifyRangeProof
	// function as it will assert that all the leaves belonging to the specified root are present.
	if len(cs.Proof) > 0 {
		proofConsStateMerkle = memorydb.New()
		defer proofConsStateMerkle.Close()
		for _, proofVal := range cs.Proof {
			proofKey := crypto.Keccak256(proofVal)
			if err := proofConsStateMerkle.Put(proofKey, proofVal); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("client path is invalid")
	}

	keyConsStateMerkle := MerkleKey{Key: cs.UpgradePath}

	verifyValueConsStateMerkle, err := trie.VerifyProof(
		common.BytesToHash(consState.StorageRoot),
		[]byte(keyConsStateMerkle.Key),
		proofConsStateMerkle,
	)
	if err != nil {
		return err
	}

	if !bytes.Equal(verifyValueConsStateMerkle, bz) {
		return errorsmod.Wrapf(err, "client state proof failed. Path: %s", keyConsStateMerkle)
	}

	// Construct new client state and consensus state
	// Relayer chosen client parameters are ignored.
	// All chain-chosen parameters come from committed client, all client-chosen parameters
	// come from current client.
	newClientState := NewClientState(
		avaUpgradeClient.ChainId,
		cs.TrustLevel,
		cs.TrustingPeriod,
		cs.MaxClockDrift,
		avaUpgradeClient.LatestHeight,
		avaUpgradeClient.UpgradePath,
		avaUpgradeClient.Proof,
	)

	if err := newClientState.Validate(); err != nil {
		return errorsmod.Wrap(err, "updated client state failed basic validation")
	}

	// The new consensus state is merely used as a trusted kernel against which headers on the new
	// chain can be verified. The root is just a stand-in sentinel value as it cannot be known in advance, thus no proof verification will pass.
	// The timestamp and the NextValidatorsHash of the consensus state is the blocktime and NextValidatorsHash
	// of the last block committed by the old chain. This will allow the first block of the new chain to be verified against
	// the last validators of the old chain so long as it is submitted within the TrustingPeriod of this client.
	// NOTE: We do not set processed time for this consensus state since this consensus state should not be used for packet verification
	// as the root is empty. The next consensus state submitted using update will be usable for packet-verification.
	newConsState := NewConsensusState(
		avaUpgradeConsState.Timestamp,
		avaUpgradeConsState.Vdrs,
		avaUpgradeConsState.StorageRoot,
		avaUpgradeConsState.SignedStorageRoot,
		avaUpgradeConsState.ValidatorSet,
		avaUpgradeConsState.SignedValidatorSet,
		avaUpgradeConsState.SignersInput,
	)

	setClientState(clientStore, cdc, newClientState)
	SetConsensusState(clientStore, cdc, newConsState, newClientState.LatestHeight)
	setConsensusMetadata(ctx, clientStore, avaUpgradeClient.LatestHeight)

	return nil
}

// VerifyMembership is a generic proof verification method which verifies a proof of the existence of a value at a given CommitmentPath at the specified height.
// The caller is expected to construct the full CommitmentPath from a CommitmentPrefix and a standardized path (as defined in ICS 24).
// If a zero proof height is passed in, it will fail to retrieve the associated consensus state.
func (cs ClientState) VerifyMembership(
	ctx sdk.Context,
	clientStore sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	proof []byte,
	path exported.Path,
	value []byte,
) error {
	if cs.GetLatestHeight().LT(height) {
		return errorsmod.Wrapf(
			ibcerrors.ErrInvalidHeight,
			"client state height < proof height (%d < %d), please ensure the client has been updated", cs.GetLatestHeight(), height,
		)
	}

	if err := verifyDelayPeriodPassed(ctx, clientStore, height, delayTimePeriod, delayBlockPeriod); err != nil {
		return err
	}

	consensusState, found := GetConsensusState(clientStore, cdc, height)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrConsensusStateNotFound, "please ensure the proof was constructed against a height that exists on the client")
	}

	vdrs, totalWeigth, err := ValidateValidatorSet(consensusState.Vdrs)
	if err != nil {
		return err
	}

	err = Verify(consensusState.SignersInput, SetSignature(consensusState.SignedValidatorSet), consensusState.ValidatorSet, vdrs, totalWeigth, cs.TrustLevel.Numerator, cs.TrustLevel.Denominator)
	if err != nil {
		return errorsmod.Wrap(err, "failed to verify ValidatorSet signature")
	}
	err = Verify(consensusState.SignersInput, SetSignature(consensusState.SignedStorageRoot), consensusState.StorageRoot, vdrs, totalWeigth, cs.TrustLevel.Numerator, cs.TrustLevel.Denominator)
	if err != nil {
		return errorsmod.Wrap(err, "failed to verify StorageRoot signature")
	}

	var proofEx ethdb.Database
	// Populate proof when ProofVals are present in the response. Its ok to pass it as nil to the trie.VerifyRangeProof
	// function as it will assert that all the leaves belonging to the specified root are present.
	if len(cs.Proof) > 0 {
		proofEx = memorydb.New()
		defer proofEx.Close()
		for _, proofVal := range cs.Proof {
			proofKey := crypto.Keccak256(proofVal)
			if err := proofEx.Put(proofKey, proofVal); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("client path is invalid")
	}

	key := path.(*MerkleKey)

	verifyValue, err := trie.VerifyProof(
		common.BytesToHash(consensusState.StorageRoot),
		[]byte(key.Key),
		proofEx,
	)
	if err != nil {
		return err
	}

	if !bytes.Equal(verifyValue, value) {
		return fmt.Errorf("key: %064x, value is not equal expected: %064x, but have: %064x", key.Key, value, verifyValue)
	}
	return nil
}

// VerifyNonMembership is a generic proof verification method which verifies the absence of a given CommitmentPath at a specified height.
// The caller is expected to construct the full CommitmentPath from a CommitmentPrefix and a standardized path (as defined in ICS 24).
// If a zero proof height is passed in, it will fail to retrieve the associated consensus state.
func (cs ClientState) VerifyNonMembership(
	ctx sdk.Context,
	clientStore sdk.KVStore,
	cdc codec.BinaryCodec,
	height exported.Height,
	delayTimePeriod uint64,
	delayBlockPeriod uint64,
	proof []byte,
	path exported.Path,
) error {
	if cs.GetLatestHeight().LT(height) {
		return errorsmod.Wrapf(
			ibcerrors.ErrInvalidHeight,
			"client state height < proof height (%d < %d), please ensure the client has been updated", cs.GetLatestHeight(), height,
		)
	}

	if err := verifyDelayPeriodPassed(ctx, clientStore, height, delayTimePeriod, delayBlockPeriod); err != nil {
		return err
	}

	consensusState, found := GetConsensusState(clientStore, cdc, height)
	if !found {
		return errorsmod.Wrap(clienttypes.ErrConsensusStateNotFound, "please ensure the proof was constructed against a height that exists on the client")
	}

	// vdrs, totalWeigth, err := ValidateValidatorSet(consensusState.Vdrs)
	// if err != nil {
	// 	return err
	// }

	// err = Verify(consensusState.SignersInput, SetSignature(consensusState.SignedValidatorSet), consensusState.ValidatorSet, vdrs, totalWeigth, cs.TrustLevel.Numerator, cs.TrustLevel.Denominator)
	// if err != nil {
	// 	return errorsmod.Wrap(err, "failed to verify ValidatorSet signature")
	// }
	// err = Verify(consensusState.SignersInput, SetSignature(consensusState.SignedStorageRoot), consensusState.StorageRoot, vdrs, totalWeigth, cs.TrustLevel.Numerator, cs.TrustLevel.Denominator)
	// if err != nil {
	// 	return errorsmod.Wrap(err, "failed to verify StorageRoot signature")
	// }

	var proofEx ethdb.Database
	// Populate proof when ProofVals are present in the response. Its ok to pass it as nil to the trie.VerifyRangeProof
	// function as it will assert that all the leaves belonging to the specified root are present.
	if len(cs.Proof) > 0 {
		proofEx = memorydb.New()
		defer proofEx.Close()
		for _, proofVal := range cs.Proof {
			proofKey := crypto.Keccak256(proofVal)
			if err := proofEx.Put(proofKey, proofVal); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("client path is invalid")
	}

	key := path.(*MerkleKey)

	verifyValue, err := trie.VerifyProof(
		common.BytesToHash(consensusState.StorageRoot),
		[]byte(key.Key),
		proofEx,
	)
	if err != nil {
		return err
	}

	if !bytes.Equal(verifyValue, nil) {
		return fmt.Errorf("value is not equal")
	}
	return nil
}
