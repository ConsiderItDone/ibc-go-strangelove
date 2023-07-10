package avalanche_test

import (
	"bytes"
	crand "crypto/rand"
	time "time"

	errorsmod "cosmossdk.io/errors"
	"github.com/ava-labs/avalanchego/ids"
	"github.com/ava-labs/avalanchego/utils"
	"github.com/ava-labs/avalanchego/utils/crypto/bls"
	"github.com/ava-labs/avalanchego/utils/set"
	"github.com/ava-labs/avalanchego/vms/platformvm/warp"
	"github.com/ava-labs/subnet-evm/core/rawdb"
	"github.com/ava-labs/subnet-evm/ethdb/memorydb"
	"github.com/ava-labs/subnet-evm/trie"
	"github.com/cosmos/cosmos-sdk/codec"
	cosmostypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/v7/modules/core/24-host"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
	ibcava "github.com/cosmos/ibc-go/v7/modules/light-clients/14-avalanche"
	ibctesting "github.com/cosmos/ibc-go/v7/testing"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// Do not change the length of these variables
	fiftyCharChainID    = "12345678901234567890123456789012345678901234567890"
	fiftyOneCharChainID = "123456789012345678901234567890123456789012345678901"
)

func (suite *AvalancheTestSuite) TestStatus() {
	var (
		path        *ibctesting.Path
		clientState *ibcava.ClientState
		marshaler   codec.Codec
	)

	interfaceRegistry := cosmostypes.NewInterfaceRegistry()
	marshaler = codec.NewProtoCodec(interfaceRegistry)

	std.RegisterInterfaces(interfaceRegistry)
	ibcava.AppModuleBasic{}.RegisterInterfaces(interfaceRegistry)

	testCases := []struct {
		name      string
		malleate  func()
		expStatus exported.Status
	}{
		{"client is active", func() {}, exported.Active},
		{"client is frozen", func() {
			clientState.FrozenHeight = clienttypes.NewHeight(0, 1)
		}, exported.Frozen},
		{"client status without consensus state", func() {
			clientState.LatestHeight = clientState.LatestHeight.Increment().(clienttypes.Height)
		}, exported.Expired},
		{"client status is expired", func() {
			suite.coordinator.IncrementTimeBy(clientState.TrustingPeriod)
		}, exported.Expired},
	}

	for _, tc := range testCases {

		clientState = ibcava.NewClientState(
			chainID,
			ibcava.Fraction{1, 1},
			trustingPeriod,
			maxClockDrift,
			newClientHeight,
			upgradePath,
			nil,
		)

		path = ibctesting.NewPath(suite.chainA, suite.chainB)
		suite.coordinator.SetupClients(path)

		clientStore := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(suite.chainA.GetContext(), path.EndpointA.ClientID)

		consensusState := &ibcava.ConsensusState{
			Timestamp: suite.chainA.GetContext().BlockTime(),
		}

		ibcava.SetConsensusState(clientStore, marshaler, consensusState, clientState.GetLatestHeight())

		tc.malleate()

		status := clientState.Status(suite.chainA.GetContext(), clientStore, marshaler)
		suite.Require().Equal(tc.expStatus, status)
	}
}

func (suite *AvalancheTestSuite) TestValidate() {
	testCases := []struct {
		name        string
		clientState *ibcava.ClientState
		expPass     bool
	}{
		{
			name:        "valid client",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift, height, upgradePath, nil),
			expPass:     true,
		},
		{
			name:        "valid client with empty upgrade path",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift, height, "", nil),
			expPass:     false,
		},
		{
			name:        "invalid chainID",
			clientState: ibcava.NewClientState("  ", ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift, height, upgradePath, nil),
			expPass:     false,
		},
		{
			// NOTE: if this test fails, the code must account for the change in chainID length across avalanche versions!
			// Do not only fix the test, fix the code!
			// https://github.com/cosmos/ibc-go/issues/177
			name:        "valid chainID - chainID validation failed for chainID of length 50! ",
			clientState: ibcava.NewClientState(fiftyCharChainID, ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift, height, upgradePath, nil),
			expPass:     true,
		},
		{
			// NOTE: if this test fails, the code must account for the change in chainID length across avalanche versions!
			// Do not only fix the test, fix the code!
			// https://github.com/cosmos/ibc-go/issues/177
			name:        "invalid chainID - chainID validation did not fail for chainID of length 51! ",
			clientState: ibcava.NewClientState(fiftyOneCharChainID, ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift, height, upgradePath, nil),
			expPass:     false,
		},
		{
			name:        "invalid zero trusting period",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, 0, maxClockDrift, height, upgradePath, nil),
			expPass:     false,
		},
		{
			name:        "invalid negative trusting period",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, -1, maxClockDrift, height, upgradePath, nil),
			expPass:     false,
		},
		{
			name:        "invalid revision number",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift, clienttypes.NewHeight(1, 1), upgradePath, nil),
			expPass:     false,
		},
		{
			name:        "invalid revision height",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift, clienttypes.ZeroHeight(), upgradePath, nil),
			expPass:     false,
		},
	}

	for _, tc := range testCases {
		err := tc.clientState.Validate()
		if tc.expPass {
			suite.Require().NoError(err, tc.name)
		} else {
			suite.Require().Error(err, tc.name)
		}
	}
}

func (suite *AvalancheTestSuite) TestInitialize() {

	interfaceRegistry := cosmostypes.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(interfaceRegistry)

	std.RegisterInterfaces(interfaceRegistry)
	ibcava.AppModuleBasic{}.RegisterInterfaces(interfaceRegistry)

	testCases := []struct {
		name           string
		consensusState exported.ConsensusState
		expPass        bool
	}{
		{
			name:           "valid consensus",
			consensusState: &ibcava.ConsensusState{},
			expPass:        true,
		},
		{
			name:           "invalid consensus: consensus state is solomachine consensus",
			consensusState: ibctesting.NewSolomachine(suite.T(), suite.chainA.Codec, "solomachine", "", 2).ConsensusState(),
			expPass:        false,
		},
	}

	for _, tc := range testCases {
		suite.SetupTest()
		path := ibctesting.NewPath(suite.chainA, suite.chainB)

		clientState := ibcava.NewClientState(
			path.EndpointB.Chain.ChainID,
			ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift,
			suite.chainB.LastHeader.GetTrustedHeight(), upgradePath, nil)

		store := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(suite.chainA.GetContext(), path.EndpointA.ClientID)

		err := clientState.Initialize(suite.chainA.GetContext(), marshaler, store, tc.consensusState)

		if tc.expPass {
			suite.Require().NoError(err, "valid case returned an error")
			suite.Require().True(store.Has(host.ClientStateKey()))
			suite.Require().True(store.Has(host.ConsensusStateKey(suite.chainB.LastHeader.GetTrustedHeight())))
		} else {
			suite.Require().Error(err, "invalid case didn't return an error")
			suite.Require().False(store.Has(host.ClientStateKey()))
			suite.Require().False(store.Has(host.ConsensusStateKey(suite.chainB.LastHeader.GetTrustedHeight())))
		}
	}
}

func (suite *AvalancheTestSuite) TestVerifyMembership() {

	var (
		testingpath      *ibctesting.Path
		delayTimePeriod  uint64
		delayBlockPeriod uint64
		proofHeight      exported.Height
		proof            [][]byte
		path             exported.Path
		value            []byte

		storageRoot []byte
	)

	interfaceRegistry := cosmostypes.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(interfaceRegistry)

	std.RegisterInterfaces(interfaceRegistry)
	ibcava.AppModuleBasic{}.RegisterInterfaces(interfaceRegistry)

	testCases := []struct {
		name     string
		malleate func()
		expPass  bool
	}{
		{
			"successful verification", func() {
			},
			true,
		},
		{
			"delay time period has passed", func() {
				delayTimePeriod = uint64(time.Second.Nanoseconds())
			},
			true,
		},
		{
			"delay time period has not passed", func() {
				delayTimePeriod = uint64(time.Hour.Nanoseconds())
			},
			false,
		},
		{
			"delay block period has passed", func() {
				delayBlockPeriod = 1
			},
			true,
		},
		{
			"delay block period has not passed", func() {
				delayBlockPeriod = 1000
			},
			false,
		},
		{
			"latest client height < height", func() {
				proofHeight = testingpath.EndpointA.GetClientState().GetLatestHeight().Increment()
			}, false,
		},
		{
			"failed to unmarshal merkle proof", func() {
				proof = nil
			}, false,
		},
		{
			"proof verification failed", func() {
				// change the value being proved
				value = []byte("invalid value")
			}, false,
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(tc.name, func() {
			suite.SetupTest() // reset

			testingpath = ibctesting.NewPath(suite.chainA, suite.chainB)
			testingpath.SetChannelOrdered()
			suite.coordinator.Setup(testingpath)

			testVdrs = []*testValidator{
				newTestValidator(),
				newTestValidator(),
				newTestValidator(),
			}
			utils.Sort(testVdrs)

			vdrs := []*ibcava.Validator{
				{
					NodeIDs:       [][]byte{testVdrs[0].nodeID.Bytes()},
					PublicKeyByte: bls.PublicKeyToBytes(testVdrs[0].vdr.PublicKey),
					Weight:        testVdrs[0].vdr.Weight,
					EndTime:       suite.chainA.GetContext().BlockTime().Add(900000000000000),
				},
				{
					NodeIDs:       [][]byte{testVdrs[1].nodeID.Bytes()},
					PublicKeyByte: bls.PublicKeyToBytes(testVdrs[1].vdr.PublicKey),
					Weight:        testVdrs[1].vdr.Weight,
					EndTime:       suite.chainA.GetContext().BlockTime().Add(900000000000000),
				},
				{
					NodeIDs:       [][]byte{testVdrs[2].nodeID.Bytes()},
					PublicKeyByte: bls.PublicKeyToBytes(testVdrs[2].vdr.PublicKey),
					Weight:        testVdrs[2].vdr.Weight,
					EndTime:       suite.chainA.GetContext().BlockTime().Add(900000000000000),
				},
			}

			chainID, _ := ids.ToID([]byte(testingpath.EndpointA.Chain.ChainID))

			// reset time and block delays to 0, malleate may change to a specific non-zero value.
			delayTimePeriod = 0
			delayBlockPeriod = 0

			trieEx, vals := randomTrie(5)
			storageRoot = trieEx.Hash().Bytes()
			prover := makeProvers(trieEx)
			_, kv := pick(vals)
			proofOut, _ := ibcava.IterateVals(prover(kv.k))
			proof = proofOut

			value = kv.v
			path = &ibcava.MerkleKey{Key: string(kv.k)}

			signers := set.NewBits()
			signers.Add(1)
			// signers.Add(2)
			signersInput := signers.Bytes()

			unsignedMsg, _ := warp.NewUnsignedMessage(
				chainID,
				ids.Empty,
				nil,
			)
			unsignedBytes := unsignedMsg.Bytes()

			vdr1Sig1 := bls.Sign(testVdrs[1].sk, unsignedBytes)
			// vdr2Sig1 := bls.Sign(testVdrs[2].sk, unsignedBytes)
			aggSig1, err := bls.AggregateSignatures([]*bls.Signature{vdr1Sig1}) //, vdr2Sig1})
			suite.NoError(err)
			signedStorageRoot := [bls.SignatureLen]byte{}
			copy(signedStorageRoot[:], bls.SignatureToBytes(aggSig1))

			vdrs1, totalWeigth, err := ibcava.ValidateValidatorSet(suite.chainA.GetContext(), vdrs)
			suite.Require().NoError(err)
			err = ibcava.Verify(signersInput, signedStorageRoot, unsignedBytes, vdrs1, totalWeigth, 1, 3)
			if err != nil {
				err = errorsmod.Wrap(err, "1-----------")
				suite.Require().NoError(err)
			}

			err = ibcava.Verify(signersInput, signedStorageRoot, unsignedBytes, vdrs1, totalWeigth, 1, 3)
			if err != nil {
				err = errorsmod.Wrap(err, "2-----------")
				suite.Require().NoError(err)
			}


			err = ibcava.Verify(signersInput, signedStorageRoot, unsignedBytes, vdrs1, totalWeigth, 1, 3)
			if err != nil {
				err = errorsmod.Wrap(err, "3-----------")
				suite.Require().NoError(err)
			}


			err = ibcava.Verify(signersInput, signedStorageRoot, unsignedBytes, vdrs1, totalWeigth, 1, 3)
			if err != nil {
				err = errorsmod.Wrap(err, "4-----------")
				suite.Require().NoError(err)
			}


			var validatorSet []byte
			for _, m := range vdrs {
				data, _ := m.Marshal()
				validatorSet = append(validatorSet, data...)
			}

			unsignedMsgValidator, _ := warp.NewUnsignedMessage(
				chainID,
				ids.Empty,
				nil,
			)
			unsignedMsgValidatorBytes := unsignedMsgValidator.Bytes()

			vdr1Sig2 := bls.Sign(testVdrs[1].sk, unsignedMsgValidatorBytes)
			vdr2Sig2 := bls.Sign(testVdrs[2].sk, unsignedMsgValidatorBytes)
			aggSig2, err := bls.AggregateSignatures([]*bls.Signature{vdr1Sig2, vdr2Sig2})
			suite.NoError(err)
			signedValidatorSet := [bls.SignatureLen]byte{}
			copy(signedValidatorSet[:], bls.SignatureToBytes(aggSig2))

			proofHeight = suite.chainB.LastHeader.GetTrustedHeight()

			suite.Require().NoError(err)

			tc.malleate() // make changes as necessary

			clientState := ibcava.NewClientState(
				testingpath.EndpointA.Chain.ChainID,
				ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift,
				suite.chainB.LastHeader.GetTrustedHeight(), upgradePath, proof)

			ctx := suite.chainA.GetContext()
			store := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(ctx, testingpath.EndpointA.ClientID)

			ibcava.SetConsensusState(store, marshaler, ibcava.NewConsensusState(
				time.Now(),
				vdrs,
				storageRoot,
				signedStorageRoot[:],
				validatorSet,
				signedValidatorSet[:],
				signersInput,
			), proofHeight)

			err = clientState.VerifyMembership(
				ctx, store, marshaler, proofHeight, delayTimePeriod, delayBlockPeriod,
				nil, path, value,
			)

			if tc.expPass {
				suite.Require().NoError(err)
			} else {
				suite.Require().Error(err)
			}
		})
	}
}

func randomTrie(n int) (*trie.Trie, map[string]*kv) {
	trieOutput := trie.NewEmpty(trie.NewDatabase(rawdb.NewMemoryDatabase()))
	vals := make(map[string]*kv)
	for i := byte(0); i < 100; i++ {
		value := &kv{common.LeftPadBytes([]byte{i}, 32), []byte{i}, false}
		value2 := &kv{common.LeftPadBytes([]byte{i + 10}, 32), []byte{i}, false}
		trieOutput.Update(value.k, value.v)
		trieOutput.Update(value2.k, value2.v)
		vals[string(value.k)] = value
		vals[string(value2.k)] = value2
	}
	for i := 0; i < n; i++ {
		value := &kv{randBytes(32), randBytes(20), false}
		trieOutput.Update(value.k, value.v)
		vals[string(value.k)] = value
	}
	return trieOutput, vals
}

type kv struct {
	k, v []byte
	t    bool
}

func randBytes(n int) []byte {
	r := make([]byte, n)
	crand.Read(r)
	return r
}

// makeProvers creates Merkle trie provers based on different implementations to
// test all variations.
func makeProvers(trieOutput *trie.Trie) func(key []byte) *memorydb.Database {
	// Create a leaf iterator based Merkle prover
	return func(key []byte) *memorydb.Database {
		proof := memorydb.New()
		if it := trie.NewIterator(trieOutput.NodeIterator(key)); it.Next() && bytes.Equal(key, it.Key) {
			for _, p := range it.Prove() {
				proof.Put(crypto.Keccak256(p), p)
			}
		}
		return proof
	}
}

func pick(m map[string]*kv) (string, *kv) {
	for i, v := range m {
		return i, v
	}
	return "", nil
}

func (suite *AvalancheTestSuite) TestVerifyNonMembership() {
	var (
		testingpath      *ibctesting.Path
		delayTimePeriod  uint64
		delayBlockPeriod uint64
		proofHeight      exported.Height
		proof            [][]byte
		path             exported.Path

		storageRoot []byte
	)

	interfaceRegistry := cosmostypes.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(interfaceRegistry)

	std.RegisterInterfaces(interfaceRegistry)
	ibcava.AppModuleBasic{}.RegisterInterfaces(interfaceRegistry)

	testCases := []struct {
		name     string
		malleate func()
		expPass  bool
	}{
		{
			"successful verification", func() {
			},
			true,
		},
		{
			"delay time period has passed", func() {
				delayTimePeriod = uint64(time.Second.Nanoseconds())
			},
			true,
		},
		{
			"delay time period has not passed", func() {
				delayTimePeriod = uint64(time.Hour.Nanoseconds())
			},
			false,
		},
		{
			"delay block period has passed", func() {
				delayBlockPeriod = 1
			},
			true,
		},
		{
			"delay block period has not passed", func() {
				delayBlockPeriod = 1000
			},
			false,
		},
		{
			"latest client height < height", func() {
				proofHeight = testingpath.EndpointA.GetClientState().GetLatestHeight().Increment()
			}, false,
		},
		{
			"failed to unmarshal merkle proof", func() {
				proof = nil
			}, false,
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			testingpath = ibctesting.NewPath(suite.chainA, suite.chainB)
			testingpath.SetChannelOrdered()
			suite.coordinator.Setup(testingpath)

			testVdrs = []*testValidator{
				newTestValidator(),
				newTestValidator(),
				newTestValidator(),
			}
			utils.Sort(testVdrs)

			vdrs := []*ibcava.Validator{
				{
					NodeIDs:       [][]byte{testVdrs[0].nodeID.Bytes()},
					PublicKeyByte: bls.PublicKeyToBytes(testVdrs[0].vdr.PublicKey),
					Weight:        testVdrs[0].vdr.Weight,
					EndTime:       suite.chainA.GetContext().BlockTime().Add(900000000000000),
				},
				{
					NodeIDs:       [][]byte{testVdrs[1].nodeID.Bytes()},
					PublicKeyByte: bls.PublicKeyToBytes(testVdrs[1].vdr.PublicKey),
					Weight:        testVdrs[1].vdr.Weight,
					EndTime:       suite.chainA.GetContext().BlockTime().Add(900000000000000),
				},
				{
					NodeIDs:       [][]byte{testVdrs[2].nodeID.Bytes()},
					PublicKeyByte: bls.PublicKeyToBytes(testVdrs[2].vdr.PublicKey),
					Weight:        testVdrs[2].vdr.Weight,
					EndTime:       suite.chainA.GetContext().BlockTime().Add(900000000000000),
				},
			}

			// reset time and block delays to 0, malleate may change to a specific non-zero value.
			delayTimePeriod = 0
			delayBlockPeriod = 0

			trieEx, vals := randomTrie(50)
			storageRoot = trieEx.Hash().Bytes()
			prover := makeProvers(trieEx)
			_, kv := pick(vals)

			proofOut := prover(kv.k)
			key := "no key"
			trieEx.Prove([]byte(key), 0, proofOut)

			proof, _ = ibcava.IterateVals(proofOut)

			path = &ibcava.MerkleKey{Key: key}

			signers := set.NewBits()
			signers.Add(1)
			signers.Add(2)
			signersInput := signers.Bytes()

			unsignedMsg, _ := warp.NewUnsignedMessage(
				sourceChainID,
				ids.Empty,
				storageRoot,
			)
			unsignedBytes := unsignedMsg.Bytes()

			vdr1Sig1 := bls.Sign(testVdrs[1].sk, unsignedBytes)
			vdr2Sig1 := bls.Sign(testVdrs[2].sk, unsignedBytes)
			aggSig1, err := bls.AggregateSignatures([]*bls.Signature{vdr1Sig1, vdr2Sig1})
			suite.NoError(err)
			signedStorageRoot := [bls.SignatureLen]byte{}
			copy(signedStorageRoot[:], bls.SignatureToBytes(aggSig1))

			var validatorSet []byte
			for _, m := range vdrs {
				data, _ := m.Marshal()
				validatorSet = append(validatorSet, data...)
			}

			unsignedMsgValidator, _ := warp.NewUnsignedMessage(
				sourceChainID,
				ids.Empty,
				validatorSet,
			)
			unsignedMsgValidatorBytes := unsignedMsgValidator.Bytes()

			vdr1Sig2 := bls.Sign(testVdrs[1].sk, unsignedMsgValidatorBytes)
			vdr2Sig2 := bls.Sign(testVdrs[2].sk, unsignedMsgValidatorBytes)
			aggSig2, err := bls.AggregateSignatures([]*bls.Signature{vdr1Sig2, vdr2Sig2})
			suite.NoError(err)
			signedValidatorSet := [bls.SignatureLen]byte{}
			copy(signedValidatorSet[:], bls.SignatureToBytes(aggSig2))

			proofHeight = suite.chainB.LastHeader.GetTrustedHeight()

			suite.Require().NoError(err)

			tc.malleate() // make changes as necessary

			clientState := ibcava.NewClientState(
				testingpath.EndpointA.Chain.ChainID,
				ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift,
				suite.chainB.LastHeader.GetTrustedHeight(), upgradePath, proof)

			ctx := suite.chainA.GetContext()
			store := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(ctx, testingpath.EndpointA.ClientID)

			ibcava.SetConsensusState(store, marshaler, ibcava.NewConsensusState(
				time.Now(),
				vdrs,
				storageRoot,
				signedStorageRoot[:],
				validatorSet,
				signedValidatorSet[:],
				signersInput,
			), proofHeight)

			err = clientState.VerifyNonMembership(
				ctx, store, marshaler, proofHeight, delayTimePeriod, delayBlockPeriod,
				nil, path,
			)

			if tc.expPass {
				suite.Require().NoError(err)
			} else {
				suite.Require().Error(err)
			}
		})
	}
}
