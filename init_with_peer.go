package main

import (
	"fmt"
	"net"
	"encoding/hex"
	"time"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/btcec"
)

func main() {
	var s *server
	s, _ = NewSimpleServer()
	
	println("start connection by noise protocol")

	// It defines a connection node
	addr, _ := net.ResolveTCPAddr("tcp", "160.16.233.215:9735")
        hexPubkey, _ := hex.DecodeString("023ea0a53af875580899da0ab0a21455d9c19160c4ea1b7774c9d4be6810b02d2c")

	var hexPubkey33 *btcec.PublicKey
	hexPubkey33, _ = btcec.ParsePubKey(hexPubkey, btcec.S256())
	var peerAddr = &lnwire.NetAddress{
                IdentityKey: hexPubkey33,
                Address:     addr,
        }
	conn, _ := brontide.Dial(s.identityPriv, peerAddr, cfg.net.Dial)

	var connReq *connmgr.ConnReq
	connReq = nil
	var inbound = false

        // With the brontide connection established, we'll now craft the local
        // feature vector to advertise to the remote node.
        localFeatures := lnwire.NewRawFeatureVector()

        // We'll signal that we understand the data loss protection feature,
        // and also that we support the new gossip query features.
        localFeatures.Set(lnwire.DataLossProtectOptional)
        localFeatures.Set(lnwire.GossipQueriesOptional)

        // We'll only request a full channel graph sync if we detect that that
        // we aren't fully synced yet.
        if s.shouldRequestGraphSync() {
                // TODO(roasbeef): only do so if gossiper doesn't have active
                // peers?
                localFeatures.Set(lnwire.InitialRoutingSync)
        }

        p, err := newPeer(conn, connReq, s, peerAddr, inbound, localFeatures)
        if err != nil {
                srvrLog.Errorf("unable to create peer %v", err)
                return
        }

	println("send Init message")
	err = p.sendInitMsg()
	if err != nil {
		println("err occurred")
		return 
	}
	println("sent Init message")

	var waitSecond = 10
	fmt.Printf("waiting for %d seconds\n", waitSecond)
	println("next is sending Ping message")
	time.Sleep(time.Duration(waitSecond) * time.Second)

	println("send Ping message")
	msg := lnwire.NewPing(1)
        err = p.writeMessage(msg)
	if err != nil {
		println("err occurred")
		return
	}
	println("sent Ping message")

	fmt.Printf("waiting for %d seconds\n", waitSecond)
	println("next is sending Ping message")
	time.Sleep(time.Duration(waitSecond) * time.Second)

	println("send Ping message")
	msg2 := lnwire.NewPing(128)
        err = p.writeMessage(msg2)
	if err != nil {
		println("err occurred")
		return
	}
	println("sent Ping message")
}
