package main

import "fmt"
import "time"
import "path/filepath"
import "crypto/tls"
import "crypto/rand"
import "github.com/lightningnetwork/lnd/channeldb"
import "github.com/lightningnetwork/lnd/keychain"
import "github.com/lightningnetwork/lnd/lnwire"
import "github.com/lightningnetwork/lnd/lnwallet"
import "github.com/lightningnetwork/lnd/signal"
import "github.com/btcsuite/btcwallet/wallet"
import "github.com/btcsuite/btcd/btcec"
import "github.com/btcsuite/btcutil"
import "github.com/btcsuite/btcd/wire"

var (
	Commit string
	cfg              *config
	shutdownChannel  = make(chan struct{})
	registeredChains = newChainRegistry()
	macaroonDatabaseDir string
	tlsCipherSuites = []uint16{
                tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        }
)

func NewSimpleServer() (*server, error) {
	loadedConfig, _ := loadConfig()
	cfg = loadedConfig
	defer func() {
                if logRotator != nil {
                        logRotator.Close()
                }
        }()

	graphDir := filepath.Join(cfg.DataDir,
		defaultGraphSubDirname,
		normalizeNetwork(activeNetParams.Name))
	chanDB, err := channeldb.Open(graphDir)
	if err != nil {
                ltndLog.Errorf("unable to open channeldb: %v", err)
                return nil, err
        }
	defer chanDB.Close()

	var (
	        privateWalletPw = lnwallet.DefaultPrivatePassphrase//[]byte("hello")
                publicWalletPw  = lnwallet.DefaultPublicPassphrase//[]byte("public")
                birthday        time.Time
                recoveryWindow  uint32
                unlockedWallet  *wallet.Wallet
        )

	activeChainControl, _, err := newChainControlFromConfig(
                cfg, chanDB, privateWalletPw, publicWalletPw, birthday,
                recoveryWindow, unlockedWallet,
        )

	idPrivKey, err := activeChainControl.wallet.DerivePrivKey(keychain.KeyDescriptor{
                KeyLocator: keychain.KeyLocator{
                        Family: keychain.KeyFamilyNodeKey,
                        Index:  0,
                },
        })
	if err != nil {
		println("error when idPrivKey")
                return nil, err
        }
	idPrivKey.Curve = btcec.S256()

	server, err := newServer(
                cfg.Listeners, chanDB, activeChainControl, idPrivKey,
        )
	if err != nil {
                println("error when newServer")
                return nil, err
        }


	nodeSigner := newNodeSigner(idPrivKey)
	var chanIDSeed [32]byte
	if _, err := rand.Read(chanIDSeed[:]); err != nil {
		print("error when rand.Read")
                return nil, err
        }

	primaryChain := registeredChains.PrimaryChain()
	registeredChains.RegisterChain(primaryChain, activeChainControl)

	chainCfg := cfg.Bitcoin
	minRemoteDelay := minBtcRemoteDelay
	maxRemoteDelay := maxBtcRemoteDelay
	if primaryChain == litecoinChain {
                chainCfg = cfg.Litecoin
                minRemoteDelay = minLtcRemoteDelay
                maxRemoteDelay = maxLtcRemoteDelay
        }

	fundingMgr, err := newFundingManager(fundingConfig{
		IDKey:              idPrivKey.PubKey(),
		Wallet:             activeChainControl.wallet,
		PublishTransaction: activeChainControl.wallet.PublishTransaction,
		Notifier:           activeChainControl.chainNotifier,
		FeeEstimator:       activeChainControl.feeEstimator,
		SignMessage: func(pubKey *btcec.PublicKey,
			msg []byte) (*btcec.Signature, error) {

			if pubKey.IsEqual(idPrivKey.PubKey()) {
				return nodeSigner.SignMessage(pubKey, msg)
			}

			return activeChainControl.msgSigner.SignMessage(
				pubKey, msg,
			)
		},
		CurrentNodeAnnouncement: func() (lnwire.NodeAnnouncement, error) {
			return server.genNodeAnnouncement(true)
		},
		SendAnnouncement: func(msg lnwire.Message) error {
			errChan := server.authGossiper.ProcessLocalAnnouncement(msg,
				idPrivKey.PubKey())
			return <-errChan
		},
		NotifyWhenOnline: server.NotifyWhenOnline,
		TempChanIDSeed:   chanIDSeed,
		FindChannel: func(chanID lnwire.ChannelID) (*lnwallet.LightningChannel, error) {
			dbChannels, err := chanDB.FetchAllChannels()
			if err != nil {
				return nil, err
			}

			for _, channel := range dbChannels {
				if chanID.IsChanPoint(&channel.FundingOutpoint) {
					// TODO(roasbeef): populate beacon
					return lnwallet.NewLightningChannel(
						activeChainControl.signer,
						server.witnessBeacon,
						channel)
				}
			}

			return nil, fmt.Errorf("unable to find channel")
		},
		DefaultRoutingPolicy: activeChainControl.routingPolicy,
		NumRequiredConfs: func(chanAmt btcutil.Amount,
			pushAmt lnwire.MilliSatoshi) uint16 {
			// For large channels we increase the number
			// of confirmations we require for the
			// channel to be considered open. As it is
			// always the responder that gets to choose
			// value, the pushAmt is value being pushed
			// to us. This means we have more to lose
			// in the case this gets re-orged out, and
			// we will require more confirmations before
			// we consider it open.
			// TODO(halseth): Use Litecoin params in case
			// of LTC channels.

			// In case the user has explicitly specified
			// a default value for the number of
			// confirmations, we use it.
			defaultConf := uint16(chainCfg.DefaultNumChanConfs)
			if defaultConf != 0 {
				return defaultConf
			}

			// If not we return a value scaled linearly
			// between 3 and 6, depending on channel size.
			// TODO(halseth): Use 1 as minimum?
			minConf := uint64(3)
			maxConf := uint64(6)
			maxChannelSize := uint64(
				lnwire.NewMSatFromSatoshis(maxFundingAmount))
			stake := lnwire.NewMSatFromSatoshis(chanAmt) + pushAmt
			conf := maxConf * uint64(stake) / maxChannelSize
			if conf < minConf {
				conf = minConf
			}
			if conf > maxConf {
				conf = maxConf
			}
			return uint16(conf)
		},
		RequiredRemoteDelay: func(chanAmt btcutil.Amount) uint16 {
			// We scale the remote CSV delay (the time the
			// remote have to claim funds in case of a unilateral
			// close) linearly from minRemoteDelay blocks
			// for small channels, to maxRemoteDelay blocks
			// for channels of size maxFundingAmount.
			// TODO(halseth): Litecoin parameter for LTC.

			// In case the user has explicitly specified
			// a default value for the remote delay, we
			// use it.
			defaultDelay := uint16(chainCfg.DefaultRemoteDelay)
			if defaultDelay > 0 {
				return defaultDelay
			}

			// If not we scale according to channel size.
			delay := uint16(btcutil.Amount(maxRemoteDelay) *
				chanAmt / maxFundingAmount)
			if delay < minRemoteDelay {
				delay = minRemoteDelay
			}
			if delay > maxRemoteDelay {
				delay = maxRemoteDelay
			}
			return delay
		},
		WatchNewChannel: func(channel *channeldb.OpenChannel,
                        peerKey *btcec.PublicKey) error {

                        // First, we'll mark this new peer as a persistent peer
                        // for re-connection purposes.
                        server.mu.Lock()
                        pubStr := string(peerKey.SerializeCompressed())
                        server.persistentPeers[pubStr] = struct{}{}
                        server.mu.Unlock()

                        // With that taken care of, we'll send this channel to
                        // the chain arb so it can react to on-chain events.
                        return server.chainArb.WatchNewChannel(channel)
                },
		ReportShortChanID: func(chanPoint wire.OutPoint) error {
			cid := lnwire.NewChanIDFromOutPoint(&chanPoint)
			return server.htlcSwitch.UpdateShortChanID(cid)
		},
		RequiredRemoteChanReserve: func(chanAmt,
			dustLimit btcutil.Amount) btcutil.Amount {

			// By default, we'll require the remote peer to maintain
			// at least 1% of the total channel capacity at all
			// times. If this value ends up dipping below the dust
			// limit, then we'll use the dust limit itself as the
			// reserve as required by BOLT #2.
			reserve := chanAmt / 100
			if reserve < dustLimit {
				reserve = dustLimit
			}

			return reserve
		},
		RequiredRemoteMaxValue: func(chanAmt btcutil.Amount) lnwire.MilliSatoshi {
			// By default, we'll allow the remote peer to fully
			// utilize the full bandwidth of the channel, minus our
			// required reserve.
			reserve := lnwire.NewMSatFromSatoshis(chanAmt / 100)
			return lnwire.NewMSatFromSatoshis(chanAmt) - reserve
		},
		RequiredRemoteMaxHTLCs: func(chanAmt btcutil.Amount) uint16 {
			// By default, we'll permit them to utilize the full
			// channel bandwidth.
			return uint16(lnwallet.MaxHTLCNumber / 2)
		},
		ZombieSweeperInterval: 1 * time.Minute,
		ReservationTimeout:    10 * time.Minute,
		MinChanSize:           btcutil.Amount(cfg.MinChanSize),
	})
	if err != nil {
		print("error when defining fundingmanager")
                return nil, err
	}
	server.fundingMgr = fundingMgr

	// If we're not in simnet mode, We'll wait until we're fully synced to
	// continue the start up of the remainder of the daemon. This ensures
	// that we don't accept any possibly invalid state transitions, or
	// accept channels with spent funds.
	if !(cfg.Bitcoin.SimNet || cfg.Litecoin.SimNet) {
                _, bestHeight, err := activeChainControl.chainIO.GetBestBlock()
                if err != nil {
                        print("error when GetBestBlock")
                	return nil, err
                }

                ltndLog.Infof("Waiting for chain backend to finish sync, "+
                        "start_height=%v", bestHeight)

                for {
			if !signal.Alive() {
                                return nil, nil
                        }

                        synced, _, err := activeChainControl.wallet.IsSynced()
                        if err != nil {
				print("error when IsSynced")
                		return nil, err
                        }

                        if synced {
                                break
                        }

                        time.Sleep(time.Second * 1)
                }

                _, bestHeight, err = activeChainControl.chainIO.GetBestBlock()
                if err != nil {
                        print("error when GetBestBlock")
                	return nil, err
                }

                ltndLog.Infof("Chain backend is fully synced (end_height=%v)!",
                        bestHeight)
        }
    
	return server, nil
}
