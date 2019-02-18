package dnssec

import (
	"crypto"
	"crypto/rsa"
	"github.com/miekg/dns"
	"strings"
)

type SigningKey struct {
	PrivKey *crypto.PrivateKey
	PubKey  *dns.DNSKEY
}

type Error struct{ err string }

// export KSK=`ldns-keygen -k -a RSASHA512  -b 1024 $DOMAIN`
// export ZSK=`ldns-keygen -a RSASHA512 -b 1024 $DOMAIN`

var zskPrivStr = `Private-key-format: v1.2
Algorithm: 10 (RSASHA512)
Modulus: mf+1Jbjr5qi2g8W04dCEqlxrTodQBhX9cWHIETpy/sOGwgfEIl2moAhSWF2xwZDGAzijwkpH7Z3vJKFxE1sMMtF/FJghN1i3eMAif/+FC3VAtC1Ax4ja0336cVWnq+yuPlXKQFFIz5/kql2dcCkwjaoOysgbhyA5iKQrNrOsUS0=
PublicExponent: AQAB
PrivateExponent: Dj/K0yK5MS6LNMYmZn6Ux+6lPy7mCKogOU2C5ZUy7r/IyEtPqp5fvI8Ij4Sb3f03VTT4chHNdf8XEZyeidvy1NwuHgwaKARIcMAnBUzHuEnrpNPBRJm6qdjAM7hIsx2r9uV3hXnI9kQWlujV8tysFw47/OL61E2N6k9KByyfbgE=
Prime1: yW1v6UY+G4d6ZiEmfL6B6qnGGD95D7RGUEyRDH4cgholVLdGQAOkCA61j0nfT3gEK4RqQQSYO1pUU+QxHPw2JQ==
Prime2: w7i53cqWr/8l11AmA+ofbLQHGXnciAq04vRF7BmLGDYEASQTrgsUE5P44gwmBFG1o4/8mlosAdK2y7QsfBDsaQ==
Exponent1: Wefi/7g+mIML+vHo/9z4mAlXRhNusbfBeq3yQCU6DEgnSXzUelYlrQMDvwU2C36CPfpIguTOHg/fe+JqmYlpkQ==
Exponent2: CD4XVcfaYL8WEONHNpL9j85lHiWLrA8HXyd6al8JBJQBxyqFyaadydVJffuU/kmSpLjDopx5jfoZyKpl1TPBQQ==
Coefficient: nNpvU/xGtG0cmJDuS/A6ult7chDRUnDiFAdwokPUhupJW04i1zjF+H5aFdCEm80nMgR58fw06dxM9EHqvcQFUw==
`
var zskPubStr = "stakey.org.	14400 IN	DNSKEY	256 3 10 AwEAAZn/tSW46+aotoPFtOHQhKpca06HUAYV/XFhyBE6cv7DhsIHxCJdpqAIUlhdscGQxgM4o8JKR+2d7yShcRNbDDLRfxSYITdYt3jAIn//hQt1QLQtQMeI2tN9+nFVp6vsrj5VykBRSM+f5KpdnXApMI2qDsrIG4cgOYikKzazrFEt"

var kskPrivStr = `Private-key-format: v1.2
Algorithm: 10 (RSASHA512)
Modulus: xgDdxUYynJCaoXnl/CYSyDLj75jylFHpnxEAmROI11S1PpU+Q9MfRjFapE1fyiht5h6Jmq082PCQQ68qgttWgBllM9lUoe7v0VMLZ48EzLbpkN0QguEe2PVaLlFMMtcwmJSTOaQ9/BLNCrYCMwaUPfp99u9+zrLlyx5H1EoQC9s=
PublicExponent: AQAB
PrivateExponent: avw+1//1CtmrY4Ks/NBJp7ivpl96+x9DXzpdm1iNwOO5RsZ3LUifBltWgZ55Go87ynJHobbnQMTC/n9gNfJzyrEnSBfn3UWmM0QjrsTiDVRwOA4Onad63AOgF1A0EI6cTDkr2H+5wjjHyk7cPD3oHlMDEdHqwCsTJspRmqYPhNk=
Prime1: 9jkX+q+X99d02k13R+DDBVRASfI6IPceLe5BV9b37Vvf97K/adC5DDYrPcokJX7b/tVXFc64CJhxc0/15nvxTQ==
Prime2: zd2cP3YEhmZlWM2IdbEu14xNqMP2VbhqQwHdHGx7+vOBTfexg7WT6zJ0vp9Bx8VUfB1qnPqAA2FiRk+A7gjdxw==
Exponent1: 7u5AYrd6lLqzXhPGKC3nkYhMSnWQCuVCl/eX2RF1zRNWpxsBvEEbEMqP84nwwaH1AbkspLDQzSaBEREK4fpsEQ==
Exponent2: gXPYfAN/hvA+zJ+6Lp/zX7GnZ/eKII8tquMyIlyJfd2/ssKOCs+Uq3J3/SJyH+gTX1S0JPBUrUuAm8wEvCoxIw==
Coefficient: BZtSnAn8xu0YHIe1Mw95vhD62eC9fKzyeW4UNCzCQQ5oYKcO58DXb8QTSbBAtfaE5pIO1elDKi7/EjeYJZsg/w==
`

var kskPubStr = "stakey.org.	14400 IN	DNSKEY	257 3 10 AwEAAcYA3cVGMpyQmqF55fwmEsgy4++Y8pRR6Z8RAJkTiNdUtT6VPkPTH0YxWqRNX8oobeYeiZqtPNjwkEOvKoLbVoAZZTPZVKHu79FTC2ePBMy26ZDdEILhHtj1Wi5RTDLXMJiUkzmkPfwSzQq2AjMGlD36ffbvfs6y5cseR9RKEAvb"

var (
	zsk  *SigningKey
	ksk  *SigningKey
	zone string
)

var (
	SignErrEmptyRrset error = &Error{err: "Cannot sign empty RRset"}
)

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

func SignRRSet(rrSet []dns.RR) (*dns.RRSIG, error) {

	// TODO should we raise an error if the RRset is empty,
	// or just silently get over the fact and return nil
	if len(rrSet) < 1 {
		return nil, SignErrEmptyRrset
	}

	p := *zsk.PrivKey

	sig := makeRRSIG(zsk.PubKey)
	err := sig.Sign(p.(*rsa.PrivateKey), rrSet)

	if err != nil {
		return nil, err
	}

	return sig, nil
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

func Initialize() {
	zone = "stakey.org."
	zsk = loadZsk()
	ksk = loadKsk()
}
