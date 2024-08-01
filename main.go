package main

import (
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	path    *string = flag.String("o", "priv.key", "private key file output path")
	prefix  *string = flag.String("p", "", "prefix (excluding 0x)")
	longOk  *bool   = flag.Bool("l", false, "accept long prefixes")
	timeOut *int64  = flag.Int64("t", 0, "maximum acceptable search time in seconds")
)

var (
	errTooLongInvalid = fmt.Errorf("prefix must be 32 characters or less")
	errTooLong        = fmt.Errorf("finding a private key for an address with this prefix is likely to take a long time; re-run with the -l flag if you wish to continue")
	errInvalid        = fmt.Errorf("prefix must be a valid hex string containing only characters in the ranges [0-9], [a-f] and [A-F]")
)

func isValidPrefix(s string) error {
	if len(s) > 32 {
		return errTooLongInvalid
	}
	for _, r := range s {
		switch {
		case r <= '9' && r >= '0':
		case r <= 'f' && r >= 'a':
		case r <= 'F' && r >= 'A':
		default:
			return errInvalid
		}
	}
	if len(s) > 5 {
		return errTooLong
	}

	return nil
}

func main() {
	flag.Parse()
	if *prefix == "" {
		flag.Usage()
		return
	}

	var err error
	if err = isValidPrefix(*prefix); err != nil {
		if !errors.Is(err, errTooLong) {
			log.Fatalln(err)
		}
		if !*longOk && *timeOut == 0 {
			log.Fatalln(err)
		}
	}
	*prefix = "0x" + *prefix

	log.Println("generating keys. this may take awhile...")

	var (
		done bool
		m    sync.Mutex
	)
	if *timeOut > 0 {
		time.AfterFunc(time.Second*time.Duration(*timeOut), func() {
			var s string
			if *timeOut > 1 {
				s = "s"
			}
			// don't want to time out while the writing the key to the filesystem if a key has already been found
			m.Lock()
			if !done {
				log.Fatalln(fmt.Errorf("operation timed out after %d second%s", *timeOut, s))
			}
			// basically not needed
			m.Unlock()
		})
	}

	var (
		priv *ecdsa.PrivateKey
		addr common.Address
	)
	for ok := false; !ok; ok = strings.HasPrefix(addr.String(), *prefix) {
		priv, err = crypto.GenerateKey()
		if err != nil {
			log.Fatalln(err)
		}
		addr = crypto.PubkeyToAddress(priv.PublicKey)
	}
	m.Lock()
	done = true
	m.Unlock()
	fmt.Println(addr)
	if err = crypto.SaveECDSA(*path, priv); err != nil {
		log.Fatalln(err)
	}
}
