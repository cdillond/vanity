package main

import (
	"crypto/ecdsa"
	"crypto/rand"
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

type keyFunc func() (*ecdsa.PrivateKey, error)

// vars used by fastRand
var (
	rbuf []byte
	bufN int
)

const RBUF_LEN = 4096

// fastRand reads random data into rbuf and then converts slices of this data into private keys.
// the beginning/end indices of the private key slice are incremented by 1 with each call, so the
// underlying bytes are reused (until rbuf is exhausted and refilled), but they are interpreted
// differently by crypto.ToECDSA. In theory, this should greatly reduce the number of syscalls
// and copies for most prefixes. This would be bad if we were producing multiple private keys,
// since it could potentially be much easier to guess private keys produced by overlapping data,
// but, because we are only after 1 key, it is probably fine.
func fastRand() (pk *ecdsa.PrivateKey, err error) {
	if bufN == 0 || bufN > RBUF_LEN-32 {
		_, err = rand.Read(rbuf)
		bufN = 0
		if err != nil {
			return pk, err
		}
	}
	pk, err = crypto.ToECDSA(rbuf[bufN : bufN+32])
	bufN++
	return pk, err
}

// flags
var (
	path    *string = flag.String("o", "priv.key", "private key file output path")
	prefix  *string = flag.String("p", "", "prefix (excluding 0x)")
	longOk  *bool   = flag.Bool("l", false, "accept long prefixes")
	useFast *bool   = flag.Bool("f", false, "use a potentially faster but less secure function to generate private keys")
	timeOut *int64  = flag.Int64("t", 0, "maximum acceptable search time in seconds")
)

// errors
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

	var k keyFunc
	if *useFast {
		k = fastRand
		rbuf = make([]byte, RBUF_LEN)
	} else {
		k = crypto.GenerateKey
	}

	var (
		priv *ecdsa.PrivateKey
		addr common.Address
	)
	for ok := false; !ok; ok = strings.HasPrefix(addr.String(), *prefix) {
		priv, err = k()
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
