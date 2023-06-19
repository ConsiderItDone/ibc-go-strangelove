package avalanche_test

import (
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/v7/modules/core/24-host"
	"github.com/cosmos/ibc-go/v7/modules/core/exported"
	ibcava "github.com/cosmos/ibc-go/v7/modules/light-clients/14-avalanche"
	ibctesting "github.com/cosmos/ibc-go/v7/testing"
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
	)

	testCases := []struct {
		name      string
		malleate  func()
		expStatus exported.Status
	}{
		{"client is active", func() {}, exported.Active},
		{"client is frozen", func() {
			clientState.FrozenHeight = clienttypes.NewHeight(0, 1)
			path.EndpointA.SetClientState(clientState)
		}, exported.Frozen},
		{"client status without consensus state", func() {
			clientState.LatestHeight = clientState.LatestHeight.Increment().(clienttypes.Height)
			path.EndpointA.SetClientState(clientState)
		}, exported.Expired},
		{"client status is expired", func() {
			suite.coordinator.IncrementTimeBy(clientState.TrustingPeriod)
		}, exported.Expired},
	}

	for _, tc := range testCases {
		path = ibctesting.NewPath(suite.chainA, suite.chainB)
		suite.coordinator.SetupClients(path)

		clientStore := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(suite.chainA.GetContext(), path.EndpointA.ClientID)
		clientState = path.EndpointA.GetClientState().(*ibcava.ClientState)

		tc.malleate()

		status := clientState.Status(suite.chainA.GetContext(), clientStore, suite.chainA.App.AppCodec())
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
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, trustingPeriod, height, upgradePath),
			expPass:     true,
		},
		{
			name:        "valid client with nil upgrade path",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, trustingPeriod, height, nil),
			expPass:     true,
		},
		{
			name:        "invalid chainID",
			clientState: ibcava.NewClientState("  ", ibcava.DefaultTrustLevel, trustingPeriod, height, upgradePath),
			expPass:     false,
		},
		{
			// NOTE: if this test fails, the code must account for the change in chainID length across avalanche versions!
			// Do not only fix the test, fix the code!
			// https://github.com/cosmos/ibc-go/issues/177
			name:        "valid chainID - chainID validation failed for chainID of length 50! ",
			clientState: ibcava.NewClientState(fiftyCharChainID, ibcava.DefaultTrustLevel, trustingPeriod, height, upgradePath),
			expPass:     true,
		},
		{
			// NOTE: if this test fails, the code must account for the change in chainID length across avalanche versions!
			// Do not only fix the test, fix the code!
			// https://github.com/cosmos/ibc-go/issues/177
			name:        "invalid chainID - chainID validation did not fail for chainID of length 51! ",
			clientState: ibcava.NewClientState(fiftyOneCharChainID, ibcava.DefaultTrustLevel, trustingPeriod, height, upgradePath),
			expPass:     false,
		},
		{
			name:        "invalid zero trusting period",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, 0, height, upgradePath),
			expPass:     false,
		},
		{
			name:        "invalid negative trusting period",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, -1, height, upgradePath),
			expPass:     false,
		},
		{
			name:        "invalid revision number",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, trustingPeriod, clienttypes.NewHeight(1, 1), upgradePath),
			expPass:     false,
		},
		{
			name:        "invalid revision height",
			clientState: ibcava.NewClientState(chainID, ibcava.DefaultTrustLevel, trustingPeriod, clienttypes.ZeroHeight(), upgradePath),
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
			ibcava.DefaultTrustLevel, trustingPeriod,
			suite.chainB.LastHeader.GetTrustedHeight(), ibctesting.UpgradePath)

		store := suite.chainA.App.GetIBCKeeper().ClientKeeper.ClientStore(suite.chainA.GetContext(), path.EndpointA.ClientID)

		

		err := clientState.Initialize(suite.chainA.GetContext(), suite.cdc, store, tc.consensusState)

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
