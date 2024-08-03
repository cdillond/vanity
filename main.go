package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type cmpFunc func(common.Address, []byte, []byte, []byte) bool

func insensitiveCmp(a common.Address, prefix, suffix, buf []byte) bool {
	hexAddr := hex.AppendEncode(buf, a[:])
	if len(prefix)+len(suffix) > len(hexAddr) {
		return false
	}

	for i := 0; i < len(prefix); i++ {
		if prefix[i] != hexAddr[i] {
			return false
		}
	}

	for i := 0; i < len(suffix); i++ {
		if suffix[i] != hexAddr[len(hexAddr)-len(suffix)+i] {
			return false
		}
	}
	return true
}

func sensitiveCmp(a common.Address, prefix, suffix, _ []byte) bool {
	hexAddr := a.Hex()
	if len(prefix)+len(suffix) > len(hexAddr) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if prefix[i] != hexAddr[i] {
			return false
		}
	}
	for i := 0; i < len(suffix); i++ {
		if suffix[i] != hexAddr[len(hexAddr)-len(suffix)+i] {
			return false
		}
	}
	return true
}

type keyFunc func() (*ecdsa.PrivateKey, error)

// the func returned by fastRand reads random data into rbuf and then converts slices of this data into private keys.
// the beginning/end indices of the private key slice are incremented by 1 with each call, so the
// underlying bytes are reused (until rbuf is exhausted and refilled), but they are interpreted
// differently by crypto.ToECDSA. In theory, this should greatly reduce the number of syscalls
// and copies for most prefixes. This would be bad if we were producing multiple private keys,
// since it could potentially be much easier to guess private keys produced by overlapping data,
// but, because we are only after 1 key, it is probably fine.
func fastRand(n int, rbuf []byte) func() (pk *ecdsa.PrivateKey, err error) {
	return func() (pk *ecdsa.PrivateKey, err error) {
		if n == 0 || n > len(rbuf)-32 {
			_, err = rand.Read(rbuf)
			n = 0
			if err != nil {
				return pk, err
			}
		}
		pk, err = crypto.ToECDSA(rbuf[n : n+32])
		n++
		return pk, err
	}
}

// errors
var (
	errTooLongInvalid = fmt.Errorf("combined length of prefix and suffix must be 32 characters or less")
	errTooLong        = fmt.Errorf("finding a private key for an address with this prefix/suffix is likely to take a long time; re-run with the -l flag if you wish to continue")
	errInvalid        = fmt.Errorf("prefix/suffix must be a valid hex string containing only characters in the ranges [0-9], [a-f] and [A-F]")
)

func isValidSubstring(s string) error {
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

type result struct {
	privKey *ecdsa.PrivateKey
	addr    common.Address
}

func main() {
	// flags
	var (
		prefix      *string = flag.String("p", "", "output address prefix (excluding 0x)")
		suffix      *string = flag.String("s", "", "output address suffix")
		path        *string = flag.String("o", "priv.key", "private key file output path")
		insensitive *bool   = flag.Bool("i", false, "accept case-insensitive solutions")
		longOk      *bool   = flag.Bool("l", false, "accept long prefixes")
		useFast     *bool   = flag.Bool("f", false, "use a potentially faster but less secure function to generate private keys")
		timeOut     *int64  = flag.Int64("t", 0, "maximum acceptable search time in seconds")
	)
	flag.Parse()
	if *prefix == "" && *suffix == "" {
		flag.Usage()
		return
	}

	var err error
	if err = isValidSubstring(*prefix + *suffix); err != nil {
		if !errors.Is(err, errTooLong) {
			log.Fatalln(err)
		}
		if !*longOk && *timeOut == 0 {
			log.Fatalln(err)
		}
	}
	var (
		bPref []byte // prefix bytes
		bSuf  []byte // suffix bytes
		cmp   cmpFunc
	)
	if *insensitive {
		bPref = bytes.ToLower([]byte(*prefix))
		bSuf = bytes.ToLower([]byte(*suffix))
		cmp = insensitiveCmp
	} else {
		bPref = []byte("0x" + *prefix)
		bSuf = []byte(*suffix)
		cmp = sensitiveCmp
	}

	log.Println("generating keys. this may take awhile...")

	timedOut := make(<-chan time.Time)
	if *timeOut > 0 {
		timedOut = time.After(time.Second * time.Duration(*timeOut))
	}

	ch := make(chan result)
	for i := 0; i < 16; i++ {
		go func() {
			var k keyFunc
			if !*useFast {
				k = crypto.GenerateKey
			} else {
				var n int
				if len(*prefix) > 5 {
					n = 1 << 20 // 1 MiB
				} else {
					n = 4 << 10 // 4 KiB
				}
				k = fastRand(n, make([]byte, n))
			}
			var (
				res result
				err error
				buf []byte
			)
			if *insensitive {
				// the buf parameter exists to save a little memory in the insensitiveCmp func.
				buf = make([]byte, 0, 64)
			}
			for ok := false; !ok; ok = cmp(res.addr, bPref, bSuf, buf) {
				res.privKey, err = k()
				if err != nil {
					log.Fatalln(err)
				}
				res.addr = crypto.PubkeyToAddress(res.privKey.PublicKey)
			}
			ch <- res
		}()
	}

	select {
	case res := <-ch:
		fmt.Println(res.addr) // print the address first in case the path is /dev/stdout
		if err = crypto.SaveECDSA(*path, res.privKey); err != nil {
			log.Fatalln(err)
		}
	case <-timedOut:
		var s string
		if len(*prefix) > 1 {
			s = "s"
		}
		log.Fatalln(fmt.Errorf("operation timed out after %d second%s", *timeOut, s))
	}
}
