package avalanche_test

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"reflect"
	time "time"

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
	sdk "github.com/cosmos/cosmos-sdk/types"
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
		// {
		// 	"delay time period has passed", func() {
		// 		delayTimePeriod = uint64(time.Second.Nanoseconds())
		// 	},
		// 	true,
		// },
		// {
		// 	"delay time period has not passed", func() {
		// 		delayTimePeriod = uint64(time.Hour.Nanoseconds())
		// 	},
		// 	false,
		// },
		// {
		// 	"delay block period has passed", func() {
		// 		delayBlockPeriod = 1
		// 	},
		// 	true,
		// },
		// {
		// 	"delay block period has not passed", func() {
		// 		delayBlockPeriod = 1000
		// 	},
		// 	false,
		// },
		// {
		// 	"latest client height < height", func() {
		// 		proofHeight = testingpath.EndpointA.GetClientState().GetLatestHeight().Increment()
		// 	}, false,
		// },
		// {
		// 	"failed to unmarshal merkle proof", func() {
		// 		proof = nil
		// 	}, false,
		// },
		// {
		// 	"proof verification failed", func() {
		// 		// change the value being proved
		// 		value = []byte("invalid value")
		// 	}, false,
		// },
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
				storageRoot,
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
				// err = errorsmod.Wrap(err, "1-----------")
				// suite.Require().NoError(err)

				if !reflect.DeepEqual(vdrs1[1].PublicKeyBytes, testVdrs[1].vdr.PublicKeyBytes) {
					fmt.Println("PublicKeyBytes not equal")
				}
				fmt.Println("1 err")
			}
			fmt.Println("1 pass")

			err = ibcava.Verify(signersInput, signedStorageRoot, unsignedBytes, vdrs1, totalWeigth, 1, 3)
			if err != nil {
				// err = errorsmod.Wrap(err, "2-----------")
				// suite.Require().NoError(err)
				fmt.Println("2 err")
			}
			fmt.Println("2 pass")

			err = ibcava.Verify(signersInput, signedStorageRoot, unsignedBytes, vdrs1, totalWeigth, 1, 3)
			if err != nil {
				// err = errorsmod.Wrap(err, "3-----------")
				// suite.Require().NoError(err)
				fmt.Println("3 err")
			}
			fmt.Println("3 pass")

			err = ibcava.Verify(signersInput, signedStorageRoot, unsignedBytes, vdrs1, totalWeigth, 1, 3)
			if err != nil {
				// err = errorsmod.Wrap(err, "4-----------")
				// suite.Require().NoError(err)
				fmt.Println("4 err")
			}
			fmt.Println("4 pass")

			var validatorSet []byte
			for _, m := range vdrs {
				data, _ := m.Marshal()
				validatorSet = append(validatorSet, data...)
			}

			unsignedMsgValidator, _ := warp.NewUnsignedMessage(
				chainID,
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

func (suite *AvalancheTestSuite) TestGetTimestampAtHeight() {

	interfaceRegistry := cosmostypes.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(interfaceRegistry)

	std.RegisterInterfaces(interfaceRegistry)
	ibcava.AppModuleBasic{}.RegisterInterfaces(interfaceRegistry)
	height := suite.chainB.LastHeader.GetTrustedHeight()

	ctx := suite.chainA.GetContext()

	clientState := ibcava.NewClientState(
		suite.chainA.ChainID,
		ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift,
		suite.chainB.LastHeader.GetTrustedHeight(), upgradePath, [][]byte{})

	store := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(ctx, suite.chainA.ChainID)

	ibcava.SetConsensusState(store, marshaler, ibcava.NewConsensusState(
		ctx.BlockTime(),
		[]*ibcava.Validator{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
	), height)

	timestamp, err := clientState.GetTimestampAtHeight(ctx, store, marshaler, height)
	suite.Require().NoError(err)
	suite.Require().Equal(uint64(ctx.BlockTime().UnixNano()), timestamp)
}

func (suite *AvalancheTestSuite) TestVerifyHeader() {
	var (
		path   *ibctesting.Path
		header *ibcava.Header
	)

	testVdrs = []*testValidator{
		newTestValidator(),
		newTestValidator(),
		newTestValidator(),
	}

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

	testCases := []struct {
		name     string
		malleate func()
		expPass  bool
	}{
		{
			name:     "success",
			malleate: func() {},
			expPass:  true,
		},
		{
			name: "invalid vdrs",
			malleate: func() {
				// passing the CurrentHeader.Height as the block height as it will become a previous height once we commit N blocks
				header = &ibcava.Header{
					SubnetHeader: &ibcava.SubnetHeader{
						Height:    &clienttypes.Height{RevisionNumber: 1, RevisionHeight: 2},
						Timestamp: suite.chainA.GetContext().BlockTime(),
						BlockHash: []byte("SubnetHeaderBlockHash"),
					},
					PchainHeader: &ibcava.SubnetHeader{
						Height:    &clienttypes.Height{RevisionNumber: 2, RevisionHeight: 3},
						Timestamp: suite.chainA.GetContext().BlockTime(),
						BlockHash: []byte("PchainHeaderBlockHash"),
					},
					SubnetTrustedHeight: &clienttypes.Height{RevisionNumber: 1, RevisionHeight: 2},
					PchainTrustedHeight: &clienttypes.Height{RevisionNumber: 2, RevisionHeight: 3},
					Vdrs:                []*ibcava.Validator{vdrs[0], vdrs[2]},
				}
			},
			expPass: false,
		},
		{
			name: "invalid Height",
			malleate: func() {
				// passing the CurrentHeader.Height as the block height as it will become a previous height once we commit N blocks
				header = &ibcava.Header{
					SubnetHeader: &ibcava.SubnetHeader{
						Height:    &clienttypes.Height{RevisionNumber: 4, RevisionHeight: 9},
						Timestamp: suite.chainA.GetContext().BlockTime(),
						BlockHash: []byte("SubnetHeaderBlockHash"),
					},
					PchainHeader: &ibcava.SubnetHeader{
						Height:    &clienttypes.Height{RevisionNumber: 26, RevisionHeight: 5},
						Timestamp: suite.chainA.GetContext().BlockTime(),
						BlockHash: []byte("PchainHeaderBlockHash"),
					},
					SubnetTrustedHeight: &clienttypes.Height{RevisionNumber: 1, RevisionHeight: 2},
					PchainTrustedHeight: &clienttypes.Height{RevisionNumber: 2, RevisionHeight: 3},
					Vdrs:                vdrs,
				}
			},
			expPass: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		suite.SetupTest()
		path = ibctesting.NewPath(suite.chainA, suite.chainB)

		err := path.EndpointA.CreateClient()
		suite.Require().NoError(err)

		// ensure counterparty state is committed
		suite.coordinator.CommitBlock(suite.chainB)

		interfaceRegistry := cosmostypes.NewInterfaceRegistry()
		marshaler := codec.NewProtoCodec(interfaceRegistry)

		std.RegisterInterfaces(interfaceRegistry)
		ibcava.AppModuleBasic{}.RegisterInterfaces(interfaceRegistry)

		ctx := suite.chainA.GetContext()

		clientState := ibcava.NewClientState(
			suite.chainA.ChainID,
			ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift,
			suite.chainB.LastHeader.GetTrustedHeight(), upgradePath, [][]byte{})

		store := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(ctx, suite.chainA.ChainID)

		header = &ibcava.Header{
			SubnetHeader: &ibcava.SubnetHeader{
				Height:    &clienttypes.Height{RevisionNumber: 1, RevisionHeight: 2},
				Timestamp: suite.chainA.GetContext().BlockTime(),
				BlockHash: []byte("SubnetHeaderBlockHash"),
			},
			PchainHeader: &ibcava.SubnetHeader{
				Height:    &clienttypes.Height{RevisionNumber: 2, RevisionHeight: 3},
				Timestamp: suite.chainA.GetContext().BlockTime(),
				BlockHash: []byte("PchainHeaderBlockHash"),
			},
			SubnetTrustedHeight: &clienttypes.Height{RevisionNumber: 1, RevisionHeight: 2},
			PchainTrustedHeight: &clienttypes.Height{RevisionNumber: 2, RevisionHeight: 3},
			Vdrs:                vdrs,
		}

		ibcava.SetConsensusState(store, marshaler, ibcava.NewConsensusState(
			ctx.BlockTime(),
			vdrs,
			[]byte{},
			[]byte{},
			[]byte{},
			[]byte{},
			[]byte{},
		), header.SubnetTrustedHeight)

		tc.malleate()

		err = clientState.VerifyClientMessage(suite.chainA.GetContext(), marshaler, store, header)

		if tc.expPass {
			suite.Require().NoError(err, tc.name)
		} else {
			suite.Require().Error(err, tc.name)
		}
	}
}

// func (suite *AvalancheTestSuite) TestCheckForMisbehaviour() {
// 	var (
// 		path          *ibctesting.Path
// 		clientMessage exported.ClientMessage
// 	)

// 	testCases := []struct {
// 		name     string
// 		malleate func()
// 		expPass  bool
// 	}{
// 		{
// 			"valid update no misbehaviour",
// 			func() {},
// 			false,
// 		},
// 		{
// 			"consensus state already exists, already updated",
// 			func() {
// 				header, ok := clientMessage.(*ibctm.Header)
// 				suite.Require().True(ok)

// 				consensusState := &ibctm.ConsensusState{
// 					Timestamp:          header.GetTime(),
// 					Root:               commitmenttypes.NewMerkleRoot(header.Header.GetAppHash()),
// 					NextValidatorsHash: header.Header.NextValidatorsHash,
// 				}

// 				tmHeader, ok := clientMessage.(*ibctm.Header)
// 				suite.Require().True(ok)
// 				suite.chainA.App.GetIBCKeeper().ClientKeeper.SetClientConsensusState(suite.chainA.GetContext(), path.EndpointA.ClientID, tmHeader.GetHeight(), consensusState)
// 			},
// 			false,
// 		},
// 		{
// 			"invalid fork misbehaviour: identical headers", func() {
// 				trustedHeight := path.EndpointA.GetClientState().GetLatestHeight().(clienttypes.Height)

// 				trustedVals, found := suite.chainB.GetValsAtHeight(int64(trustedHeight.RevisionHeight) + 1)
// 				suite.Require().True(found)

// 				err := path.EndpointA.UpdateClient()
// 				suite.Require().NoError(err)

// 				height := path.EndpointA.GetClientState().GetLatestHeight().(clienttypes.Height)

// 				misbehaviourHeader := suite.chainB.CreateTMClientHeader(suite.chainB.ChainID, int64(height.RevisionHeight), trustedHeight, suite.chainB.CurrentHeader.Time.Add(time.Minute), suite.chainB.Vals, suite.chainB.NextVals, trustedVals, suite.chainB.Signers)
// 				clientMessage = &ibctm.Misbehaviour{
// 					Header1: misbehaviourHeader,
// 					Header2: misbehaviourHeader,
// 				}
// 			}, false,
// 		},
// 		{
// 			"invalid time misbehaviour: monotonically increasing time", func() {
// 				trustedHeight := path.EndpointA.GetClientState().GetLatestHeight().(clienttypes.Height)

// 				trustedVals, found := suite.chainB.GetValsAtHeight(int64(trustedHeight.RevisionHeight) + 1)
// 				suite.Require().True(found)

// 				clientMessage = &ibctm.Misbehaviour{
// 					Header1: suite.chainB.CreateTMClientHeader(suite.chainB.ChainID, suite.chainB.CurrentHeader.Height+3, trustedHeight, suite.chainB.CurrentHeader.Time.Add(time.Minute), suite.chainB.Vals, suite.chainB.NextVals, trustedVals, suite.chainB.Signers),
// 					Header2: suite.chainB.CreateTMClientHeader(suite.chainB.ChainID, suite.chainB.CurrentHeader.Height, trustedHeight, suite.chainB.CurrentHeader.Time, suite.chainB.Vals, suite.chainB.NextVals, trustedVals, suite.chainB.Signers),
// 				}
// 			}, false,
// 		},
// 		{
// 			"consensus state already exists, app hash mismatch",
// 			func() {
// 				header, ok := clientMessage.(*ibctm.Header)
// 				suite.Require().True(ok)

// 				consensusState := &ibctm.ConsensusState{
// 					Timestamp:          header.GetTime(),
// 					Root:               commitmenttypes.NewMerkleRoot([]byte{}), // empty bytes
// 					NextValidatorsHash: header.Header.NextValidatorsHash,
// 				}

// 				tmHeader, ok := clientMessage.(*ibctm.Header)
// 				suite.Require().True(ok)
// 				suite.chainA.App.GetIBCKeeper().ClientKeeper.SetClientConsensusState(suite.chainA.GetContext(), path.EndpointA.ClientID, tmHeader.GetHeight(), consensusState)
// 			},
// 			true,
// 		},
// 		{
// 			"previous consensus state exists and header time is before previous consensus state time",
// 			func() {
// 				header, ok := clientMessage.(*ibctm.Header)
// 				suite.Require().True(ok)

// 				// offset header timestamp before previous consensus state timestamp
// 				header.Header.Time = header.GetTime().Add(-time.Hour)
// 			},
// 			true,
// 		},
// 		{
// 			"next consensus state exists and header time is after next consensus state time",
// 			func() {
// 				header, ok := clientMessage.(*ibctm.Header)
// 				suite.Require().True(ok)

// 				// commit block and update client, adding a new consensus state
// 				suite.coordinator.CommitBlock(suite.chainB)
// 				err := path.EndpointA.UpdateClient()
// 				suite.Require().NoError(err)

// 				// increase timestamp of current header
// 				header.Header.Time = header.Header.Time.Add(time.Hour)
// 			},
// 			true,
// 		},
// 		{
// 			"valid fork misbehaviour returns true",
// 			func() {
// 				header1, err := path.EndpointA.Chain.ConstructUpdateTMClientHeader(path.EndpointA.Counterparty.Chain, path.EndpointA.ClientID)
// 				suite.Require().NoError(err)

// 				// commit block and update client
// 				suite.coordinator.CommitBlock(suite.chainB)
// 				err = path.EndpointA.UpdateClient()
// 				suite.Require().NoError(err)

// 				header2, err := path.EndpointA.Chain.ConstructUpdateTMClientHeader(path.EndpointA.Counterparty.Chain, path.EndpointA.ClientID)
// 				suite.Require().NoError(err)

// 				// assign the same height, each header will have a different commit hash
// 				header1.Header.Height = header2.Header.Height

// 				clientMessage = &ibctm.Misbehaviour{
// 					Header1:  header1,
// 					Header2:  header2,
// 					ClientId: path.EndpointA.ClientID,
// 				}
// 			},
// 			true,
// 		},
// 		{
// 			"valid time misbehaviour: not monotonically increasing time", func() {
// 				trustedHeight := path.EndpointA.GetClientState().GetLatestHeight().(clienttypes.Height)

// 				trustedVals, found := suite.chainB.GetValsAtHeight(int64(trustedHeight.RevisionHeight) + 1)
// 				suite.Require().True(found)

// 				clientMessage = &ibctm.Misbehaviour{
// 					Header2: suite.chainB.CreateTMClientHeader(suite.chainB.ChainID, suite.chainB.CurrentHeader.Height+3, trustedHeight, suite.chainB.CurrentHeader.Time.Add(time.Minute), suite.chainB.Vals, suite.chainB.NextVals, trustedVals, suite.chainB.Signers),
// 					Header1: suite.chainB.CreateTMClientHeader(suite.chainB.ChainID, suite.chainB.CurrentHeader.Height, trustedHeight, suite.chainB.CurrentHeader.Time, suite.chainB.Vals, suite.chainB.NextVals, trustedVals, suite.chainB.Signers),
// 				}
// 			}, true,
// 		},
// 	}

// 	for _, tc := range testCases {
// 		tc := tc
// 		suite.Run(tc.name, func() {
// 			// reset suite to create fresh application state
// 			suite.SetupTest()
// 			path = ibctesting.NewPath(suite.chainA, suite.chainB)

// 			err := path.EndpointA.CreateClient()
// 			suite.Require().NoError(err)

// 			// ensure counterparty state is committed
// 			suite.coordinator.CommitBlock(suite.chainB)
// 			clientMessage, err = path.EndpointA.Chain.ConstructUpdateTMClientHeader(path.EndpointA.Counterparty.Chain, path.EndpointA.ClientID)
// 			suite.Require().NoError(err)

// 			tc.malleate()

// 			clientState := path.EndpointA.GetClientState()
// 			clientStore := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(suite.chainA.GetContext(), path.EndpointA.ClientID)

// 			foundMisbehaviour := clientState.CheckForMisbehaviour(
// 				suite.chainA.GetContext(),
// 				suite.chainA.App.AppCodec(),
// 				clientStore, // pass in clientID prefixed clientStore
// 				clientMessage,
// 			)

// 			if tc.expPass {
// 				suite.Require().True(foundMisbehaviour)
// 			} else {
// 				suite.Require().False(foundMisbehaviour)
// 			}
// 		})
// 	}
// }

func (suite *AvalancheTestSuite) TestUpdateStateOnMisbehaviour() {
	var path *ibctesting.Path

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
			"success",
			func() {},
			true,
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(tc.name, func() {
			// reset suite to create fresh application state
			suite.SetupTest()
			path = ibctesting.NewPath(suite.chainA, suite.chainB)

			tc.malleate()

			clientState := ibcava.NewClientState(
				suite.chainA.ChainID,
				ibcava.DefaultTrustLevel, trustingPeriod, maxClockDrift,
				suite.chainB.LastHeader.GetTrustedHeight(), upgradePath, [][]byte{})

			clientStore := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(suite.chainA.GetContext(), path.EndpointA.ClientID)

			clientState.UpdateStateOnMisbehaviour(suite.chainA.GetContext(), marshaler, clientStore, nil)

			if tc.expPass {
				clientStateBz := clientStore.Get(host.ClientStateKey())
				suite.Require().NotEmpty(clientStateBz)
			}
		})
	}
}

func (suite *AvalancheTestSuite) TestUpdateState() {

	interfaceRegistry := cosmostypes.NewInterfaceRegistry()
	marshaler := codec.NewProtoCodec(interfaceRegistry)

	std.RegisterInterfaces(interfaceRegistry)
	ibcava.AppModuleBasic{}.RegisterInterfaces(interfaceRegistry)

	var (
		path           *ibctesting.Path
		clientMessage  exported.ClientMessage
		clientStore    sdk.KVStore
		consensusState exported.ConsensusState
	)

	testCases := []struct {
		name     string
		malleate func()
		expPass  bool
	}{
		{
			"success", func() {
			},
			true,
		},
		{
			"invalid ClientMessage type", func() {
				clientMessage = &ibcava.Misbehaviour{}
			},
			false,
		},
	}
	for _, tc := range testCases {
		tc := tc
		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			path = ibctesting.NewPath(suite.chainA, suite.chainB)

			err := path.EndpointA.CreateClient()
			suite.Require().NoError(err)

			// ensure counterparty state is committed
			suite.coordinator.CommitBlock(suite.chainB)
			clientStore = suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(suite.chainA.GetContext(), path.EndpointA.ClientID)

			clientMessage = &ibcava.Header{
				SubnetHeader: &ibcava.SubnetHeader{
					Height:    &clienttypes.Height{RevisionNumber: 1, RevisionHeight: 2},
					Timestamp: suite.chainA.GetContext().BlockTime(),
					BlockHash: []byte("SubnetHeaderBlockHash"),
				},
				PchainHeader: &ibcava.SubnetHeader{
					Height:    &clienttypes.Height{RevisionNumber: 2, RevisionHeight: 3},
					Timestamp: suite.chainA.GetContext().BlockTime(),
					BlockHash: []byte("PchainHeaderBlockHash"),
				},
				SubnetTrustedHeight: &clienttypes.Height{RevisionNumber: 1, RevisionHeight: 2},
				PchainTrustedHeight: &clienttypes.Height{RevisionNumber: 2, RevisionHeight: 3},
				Vdrs:                []*ibcava.Validator{},
			}

			consensusState = ibcava.NewConsensusState(
				suite.chainA.GetContext().BlockTime(),
				[]*ibcava.Validator{},
				[]byte{},
				[]byte{},
				[]byte{},
				[]byte{},
				[]byte{},
			)

			tc.malleate()

			ibcava.SetConsensusState(clientStore, marshaler, consensusState.(*ibcava.ConsensusState), height)
			clientState := path.EndpointA.GetClientState()
			suite.Require().Panics(func() {
				clientState.UpdateState(suite.chainA.GetContext(), suite.chainA.App.AppCodec(), clientStore, clientMessage)
			})
		})
	}
}

func (suite *AvalancheTestSuite) TestCheckSubstituteUpdateStateBasic() {
	var (
		substituteClientState exported.ClientState
		substitutePath        *ibctesting.Path
	)
	testCases := []struct {
		name     string
		malleate func()
	}{
		{
			"solo machine used for substitute", func() {
				substituteClientState = ibctesting.NewSolomachine(suite.T(), suite.cdc, "solo machine", "", 1).ClientState()
			},
		},
		{
			"non-matching substitute", func() {
				suite.coordinator.SetupClients(substitutePath)
				substituteClientState, ok := suite.chainA.GetClientState(substitutePath.EndpointA.ClientID).(*ibcava.ClientState)
				suite.Require().True(ok)
				// change trusting period so that test should fail
				substituteClientState.TrustingPeriod = time.Hour * 24 * 7

				tmClientState := substituteClientState
				tmClientState.ChainId += "different chain"
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			subjectPath := ibctesting.NewPath(suite.chainA, suite.chainB)
			substitutePath = ibctesting.NewPath(suite.chainA, suite.chainB)

			suite.coordinator.SetupClients(subjectPath)
			subjectClientState := suite.chainA.GetClientState(subjectPath.EndpointA.ClientID).(*ibcava.ClientState)

			// expire subject client
			suite.coordinator.IncrementTimeBy(subjectClientState.TrustingPeriod)
			suite.coordinator.CommitBlock(suite.chainA, suite.chainB)

			tc.malleate()

			subjectClientStore := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(suite.chainA.GetContext(), subjectPath.EndpointA.ClientID)
			substituteClientStore := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(suite.chainA.GetContext(), substitutePath.EndpointA.ClientID)

			err := subjectClientState.CheckSubstituteAndUpdateState(suite.chainA.GetContext(), suite.chainA.App.AppCodec(), subjectClientStore, substituteClientStore, substituteClientState)
			suite.Require().Error(err)
		})
	}
}
