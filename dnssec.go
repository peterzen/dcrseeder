package main

import (
	"crypto"
	"crypto/rsa"
	"github.com/miekg/dns"
	"strings"
)

type ZSK struct {
	zone    string
	PrivKey *crypto.PrivateKey
	PubKey  *dns.DNSKEY
}

var privStr = `Private-key-format: v1.2
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

var pubStr = "stakey.org.	IN	DNSKEY	256 3 10 AwEAAZn/tSW46+aotoPFtOHQhKpca06HUAYV/XFhyBE6cv7DhsIHxCJdpqAIUlhdscGQxgM4o8JKR+2d7yShcRNbDDLRfxSYITdYt3jAIn//hQt1QLQtQMeI2tN9+nFVp6vsrj5VykBRSM+f5KpdnXApMI2qDsrIG4cgOYikKzazrFEt"

var zsk = getZSK()

func getZSK() (zsk *ZSK) {

	pubKey, err := dns.ReadRR(strings.NewReader(pubStr), "Kstakey.org.+010+62942.key")
	if err != nil {
		return nil
	}

	k := pubKey.(*dns.DNSKEY)

	privKey, err := k.ReadPrivateKey(strings.NewReader(privStr),
		"Kstakey.org.+010+62942.private")
	if err != nil {
		return nil
	}

	return &ZSK{
		zone:    "stakey.org.",
		PubKey:  pubKey.(*dns.DNSKEY),
		PrivKey: &privKey,
	}
}

func (zsk *ZSK) SignRR(rr *dns.RR) (signature *dns.RRSIG) {

	k := zsk.PubKey
	p := zsk.PrivKey

	sig := new(dns.RRSIG)
	sig.Hdr = dns.RR_Header{zsk.zone, dns.TypeRRSIG, dns.ClassINET, 14400, 0}
	sig.Expiration = 1296534305 // date -u '+%s' -d"2011-02-01 04:25:05"
	sig.Inception = 1293942305  // date -u '+%s' -d"2011-01-02 04:25:05"
	sig.KeyTag = k.KeyTag()
	sig.SignerName = k.Hdr.Name
	sig.Algorithm = k.Algorithm

	err := sig.Sign((*p).(*rsa.PrivateKey), []dns.RR{*rr})

	if err != nil {
		return nil
	}

	return sig
}
