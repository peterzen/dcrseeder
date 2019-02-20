package dnssec

import (
	"crypto"
	"crypto/rsa"
	"github.com/miekg/dns"
	"log"
	"strings"
)

type SigningKey struct {
	PrivKey *crypto.PrivateKey
	PubKey  *dns.DNSKEY
}

// export KSK=`ldns-keygen -k -a RSASHA512  -b 1024 $DOMAIN`
// export ZSK=`ldns-keygen -a RSASHA512 -b 1024 $DOMAIN`

var zskPrivStr = `Private-key-format: v1.2
Algorithm: 10 (RSASHA512)
Modulus: 5RXbNyuZTYQOzYPMFbOoPfKZm6EVtMkuiz70xNqdoSc7hHR3hUz2Qu48HeEGNGxW+K25acKjwWQO8I51ofrolWfiuKrR2FcteQgCfVdhI53+YNSAwN4/IM/PMVzaSim+DTO9v5c4feYr5NnvG5vBzVkto7Sv7/4X5msj2hu27fE=
PublicExponent: AQAB
PrivateExponent: KWlNCmkYOln/7wi/MMEcTa54NBjnepnPjx5fUuKOEh6sdKI1JOSns6urNF+EJp/bDPMijErCHWiABt5Jx3E678ecOK2iP0OoK84inCXmpNmK6OTBvjc2EToJ2cYFvbYVxaIn+rJx+hCeto5UteSMksCDCAqD8mWS0oE8koAINRE=
Prime1: 9AupeSX33rtcr8WJ198DK7H4qjVeHGTtuukQB90W3xMDrtWsXUV0/fpXaWdHNPDGqerKpABlAlpvk7JAMcRtLQ==
Prime2: 8E6X34Qj73U2YHDDV7ANCabqu6o/y4xxAqNGyGmTENqgPg87xukxFikOcYTSPDGcdCTdT3Ak+nXfVzcXFLImVQ==
Exponent1: 3h2/IYRtFUtyEIi57MANIrfYmxH3leBGftegv4d6SY4EzButxTZyRLaU2FondQevyPbpeFrjlEC7TLHvu1wMAQ==
Exponent2: xD5qqI4xCoyeK4PrAuEyxH8bksYl8wRuBclxNJmDEHB6DDREjNxCyeYddXcSeTXKns68LPNYP3GjQoYqwyv5QQ==
Coefficient: oLV/tUX4/s4YaVRnLzIN6xekaH+fmK28PcO8gSoigY4Ih8uaxVaIcyb5NZawAVXr+eE6JovZGsbnKk1oJ7GRWw==
`
var zskPubStr = "testnet-seed.stakey.org.	IN	DNSKEY	256 3 10 AwEAAeUV2zcrmU2EDs2DzBWzqD3ymZuhFbTJLos+9MTanaEnO4R0d4VM9kLuPB3hBjRsVvituWnCo8FkDvCOdaH66JVn4riq0dhXLXkIAn1XYSOd/mDUgMDePyDPzzFc2kopvg0zvb+XOH3mK+TZ7xubwc1ZLaO0r+/+F+ZrI9obtu3x"

var kskPrivStr = `Private-key-format: v1.2
Algorithm: 10 (RSASHA512)
Modulus: rVLnexmHWdxGkcG0lPpOOq0Wz3jCdOoYIabuuteW9dqItLFa3I1NvOTuthaCwERvRaJHGh8pJN3j253c+Y8S0veDb6ZFjb7FDI4oIhWmSQUZ0wQwU40qDsZsC7dsPwr9GhAIugtunTnQ+k/HbCxNE3miYBjZPrmoznNgl8kzdKU=
PublicExponent: AQAB
PrivateExponent: glOnaYHNq70ddzYfUjJQpoBGeaUFGyJ3GL7MHcREaAN17eC6QMMjpBjEgji1AluzC7o1Gqg5qNYMIrQ2V5TEgo7+TSPRnEbh42324Pl8fHaL/Hh97AVXzIID/KiCawdlpEnTr0H0z8csJRVSFRPLl3uJ00YCRbKTIbQxAzWk7DU=
Prime1: 1DPoqd5PClbT+1nVtL4vUnIcjkuv08o5MjPGivHXgRVaBqgvDjEqZv+UIFEp+OX40BV+FFvIsqi6VMjOL1uqHw==
Prime2: 0RjDCIY6FX8g+UdwVKOZvepVCbJZo1v4VXpx1kX9faGkKdsYesujynMJmBYqkIicIRK/DoDG5GHfD+yJAlvQuw==
Exponent1: zqjTEQPpNCeFgQdnQgPqMD/joY0Cap9J/qM/27dVamgx6cPHN+oX4oFLcAG7f6PwIi6cQBV3Ks95z/JUIvkBfw==
Exponent2: G5KKVVtt2VvUO0riUybnpRV7dTXhgBsmmg71Z+3+yUxBW4uapMapqI6W20lA/6IkBHB2ZTEyCPem9HCaeIcm9Q==
Coefficient: q9RyLYzWlhSDGYPnsvb1cOHDuoWZzqh4pBJrq7eC0BF/713q31NmLWCnIH8FU41a44K3QQDg1aLEPZbN9YMziA==
`

var kskPubStr = "testnet-seed.stakey.org.	IN	DNSKEY	257 3 10 AwEAAa1S53sZh1ncRpHBtJT6TjqtFs94wnTqGCGm7rrXlvXaiLSxWtyNTbzk7rYWgsBEb0WiRxofKSTd49ud3PmPEtL3g2+mRY2+xQyOKCIVpkkFGdMEMFONKg7GbAu3bD8K/RoQCLoLbp050PpPx2wsTRN5omAY2T65qM5zYJfJM3Sl"

var (
	zsk           *SigningKey
	ksk           *SigningKey
	zone          string
	keyStorageDir string
)

var (
	SignErrEmptyRrset error = &Error{err: "Cannot sign empty RRset"}
)

type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "dnssec: <nil>"
	}
	return "dnssec: " + e.err
}

func loadZsk() (zsk *SigningKey) {

	pubKey, err := dns.ReadRR(strings.NewReader(zskPubStr), "Kstakey.org.+010+62942.key")
	if err != nil {
		return nil
	}

	k := pubKey.(*dns.DNSKEY)

	privKey, err := k.ReadPrivateKey(strings.NewReader(zskPrivStr),
		"Kstakey.org.+010+62942.private")
	if err != nil {
		return nil
	}

	return &SigningKey{
		PubKey:  pubKey.(*dns.DNSKEY),
		PrivKey: &privKey,
	}
}

func loadKsk() (ksk *SigningKey) {

	pubKey, err := dns.ReadRR(strings.NewReader(kskPubStr), "Kstakey.org.+010+55254.key")
	if err != nil {
		return nil
	}

	k := pubKey.(*dns.DNSKEY)

	privKey, err := k.ReadPrivateKey(strings.NewReader(kskPrivStr),
		"Kstakey.org.+010+55254.private")
	if err != nil {
		return nil
	}

	return &SigningKey{
		PubKey:  pubKey.(*dns.DNSKEY),
		PrivKey: &privKey,
	}
}

func makeRRSIG(k *dns.DNSKEY) *dns.RRSIG {

	sig := new(dns.RRSIG)
	sig.Hdr = dns.RR_Header{zone, dns.TypeRRSIG, dns.ClassINET, 14400, 0}
	sig.Expiration = 1552923667 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1550504467  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = k.KeyTag()
	sig.SignerName = k.Hdr.Name
	sig.Algorithm = k.Algorithm
	return sig
}

func SignRRSet(rrSet []dns.RR) ([]dns.RR, error) {

	if rrSet == nil {
		return rrSet, nil
	}

	// TODO should we raise an error if the RRset is empty,
	// or just silently get over the fact and return nil
	if len(rrSet) < 1 {
		return rrSet, nil
	}

	p := *zsk.PrivKey

	sig := makeRRSIG(zsk.PubKey)
	err := sig.Sign(p.(*rsa.PrivateKey), rrSet)

	if err != nil {
		log.Printf("DNSSEC: cannot sign RR %v", err)
		return rrSet, err
	}

	rrSet = append(rrSet, sig)

	return rrSet, nil
}

func getDNSKEY() (rrset []dns.RR) {
	zsk, _ := dns.NewRR(zskPubStr)
	// TODO add error handling
	ksk, _ := dns.NewRR(kskPubStr)
	// TODO add error handling
	return []dns.RR{zsk, ksk}
}

func GetSignedDNSKEY() ([]dns.RR, *dns.RRSIG, error) {

	rrSet := getDNSKEY()
	pubKey := ksk.PubKey
	privKey := *ksk.PrivKey

	sig := makeRRSIG(pubKey)
	err := sig.Sign(privKey.(*rsa.PrivateKey), rrSet)

	if err != nil {
		return nil, nil, err
	}

	return rrSet, sig, nil
}

func Initialize(appDatadir string, hostname string) {
	zone = hostname
	keyStorageDir = appDatadir
	zsk = loadZsk()
	ksk = loadKsk()
}
