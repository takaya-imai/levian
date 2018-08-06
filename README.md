# Levian

This is a lightning hands-on tools based on lnd library.

## How to use

```
$ go get -u github.com/golang/dep/cmd/dep
$ git clone https://github.com/lightningnetwork/lnd.git $GOPATH/src/github.com/lightningnetwork/lnd
$ cd $GOPATH/src/github.com/lightningnetwork/lnd
$ dep ensure -v

$ git clone https://github.com/takaya-imai/levian.git $GOPATH/src/github.com/takaya-imai/levian
$ cd $GOPATH/src/github.com/takaya-imai/levian
$ vi init_with_peer.go # edit parameters, "addr" and "hexPubkey" and set them to values correspondint to your node. The addr is IP address of your node and hexPubkey is your lightning node id.

$ cp simpleserver.go init_with_peer.go init_with_peer.sh $GOPATH/src/github.com/lightningnetwork/lnd
$ cd $GOPATH/src/github.com/lightningnetwork/lnd
$ sh init_with_peer.sh
```

## lnd commit

Th following commit is needed to work as a lastest commit at least.

```
commit f0f5e11b826e020c11c37343bcbaf9725627378b
Merge: d0179eb e313800
Author: Conner Fromknecht <conner@lightning.engineering>
Date:   Fri Aug 3 03:13:58 2018 -0700

    Merge pull request #1661 from cfromknecht/restore-linter

    Makefile: Restore linter
```
