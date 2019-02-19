package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	DefaultTimeout time.Duration = 5 * time.Second
)

type ChainOfTrust struct {
	soa         []dns.RR
	soaRrsig    *dns.RRSIG
	dnskey      []dns.RR
	dnskeyRrsig *dns.RRSIG
	ds          []dns.DS
	dsRrsig     *dns.RRSIG
	aaaaRrsig   *dns.RRSIG
	aRr         []dns.RR
	aaaaRr      []dns.RR
	aRrsig      *dns.RRSIG
}

type ValidationKeys struct {
	zsk *dns.DNSKEY
	ksk *dns.DNSKEY
}

type Error struct{ err string }

func (e *Error) Error() string {
	if e == nil {
		return "dnssec: <nil>"
	}
	return "dnssec: " + e.err
}

var (
	dnsMessage     *dns.Msg
	dnsClient      *dns.Client
	conf           *dns.ClientConfig
	chainOfTrust   *ChainOfTrust
	validationKeys *ValidationKeys
	ips            []string
)

func localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	dnsMessage.SetQuestion(qname, qtype)
	for _, server := range conf.Servers {
		r, _, err := dnsClient.Exchange(dnsMessage, server+":"+conf.Port)
		if err != nil {
			return nil, err
		}
		if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, errors.New("No name server to answer the question")
}

func main() {

	chainOfTrust = &ChainOfTrust{}
	validationKeys = &ValidationKeys{}

	ips = make([]string, 0, 100)

	hostname := "seed.stakey.org."
	var err error

	//conf = &dns.ClientConfig{
	//	Ndots:   1,
	//	Servers: []string{"localhost"},
	//	Port:    "5453",
	//}
	//conf, err = &dns.ClientConfig{["localhost"], "", "5453", 1, DefaultTimeout, 1, 1)
	conf, err = dns.ClientConfigFromFile("resolv.conf")
	if err != nil || conf == nil {
		fmt.Printf("Cannot initialize the local resolver: %s\n", err)
		os.Exit(1)
	}

	err = LookupIP(hostname)

	if err != nil {
		fmt.Printf("Validation failed: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("validation successful")
}

func LookupIP(hostname string) (err error) {

	zone := "stakey.org."
	qname := dns.Fqdn(zone)
	fmt.Printf("fqdn %s\n", qname)

	// get SOA
	dnsMessage = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1),
	}
	dnsMessage.SetEdns0(4096, true)
	dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	r, err := localQuery(qname, dns.TypeSOA)
	if err != nil || r == nil {
		fmt.Printf("Cannot retrieve SOA for %s: %s\n", qname, err)
		return err
	}
	if r.Rcode == dns.RcodeNameError {
		fmt.Printf("No such domain %s\n", qname)
		return err
	}

	chainOfTrust.soa = make([]dns.RR, 0, 1)

	for _, ans := range r.Answer {
		switch t := ans.(type) {
		case *dns.RRSIG:
			chainOfTrust.soaRrsig = t
		case *dns.SOA:
			chainOfTrust.soa = append(chainOfTrust.soa, t)
		}
	}

	// get DS record from parent
	dnsMessage = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1),
	}
	dnsMessage.SetEdns0(4096, true)
	dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	r, err = localQuery(qname, dns.TypeDS)
	if err != nil || r == nil {
		fmt.Printf("Cannot retrieve DS for %s: %s\n", qname, err)
		return err
	}
	if r.Rcode == dns.RcodeNameError {
		fmt.Printf("No such domain %s\n", qname)
		return err
	}
	chainOfTrust.ds = make([]dns.DS, 0, len(r.Answer))

	for _, ans := range r.Answer {
		switch t := ans.(type) {
		case *dns.RRSIG:
			chainOfTrust.dsRrsig = t
		case *dns.DS:
			chainOfTrust.ds = append(chainOfTrust.ds, *t)
		}
	}

	// get DNSKEY records
	dnsMessage = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1),
	}
	dnsMessage.SetEdns0(4096, true)
	dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	r, err = localQuery(qname, dns.TypeDNSKEY)
	if err != nil || r == nil {
		fmt.Printf("Cannot retrieve DNSKEY %s: %s\n", qname, err)
		return err
	}
	if r.Rcode == dns.RcodeNameError {
		fmt.Printf("No such domain %s\n", qname)
		return err
	}

	chainOfTrust.dnskey = make([]dns.RR, 0, 2)

	for _, ans := range r.Answer {
		switch t := ans.(type) {
		case *dns.DNSKEY:
			chainOfTrust.dnskey = append(chainOfTrust.dnskey, ans)
			if t.Flags == 256 {
				validationKeys.zsk = t
				break
			}
			if t.Flags == 257 {
				validationKeys.ksk = t
				break
			}
		case *dns.RRSIG:
			chainOfTrust.dnskeyRrsig = t
		}
	}

	// get A records for the seed host
	qname = hostname
	dnsMessage = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1),
	}
	dnsMessage.SetEdns0(4096, true)
	dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	r, err = localQuery(qname, dns.TypeA)
	if err != nil || r == nil {
		fmt.Printf("Cannot retrieve A %s: %s\n", qname, err)
		return err
	}
	if r.Rcode == dns.RcodeNameError {
		fmt.Printf("No such domain %s\n", qname)
		return err
	}

	chainOfTrust.aRr = make([]dns.RR, 0, len(r.Answer))

	for _, ans := range r.Answer {
		switch t := ans.(type) {
		case *dns.A:
			chainOfTrust.aRr = append(chainOfTrust.aRr, ans)
			//ips = append(ips, t.A.String())
		case *dns.RRSIG:
			chainOfTrust.aRrsig = t
		}
	}

	// get AAAA records for the seed host
	qname = hostname
	dnsMessage = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1),
	}
	dnsMessage.SetEdns0(4096, true)
	dnsClient = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	r, err = localQuery(qname, dns.TypeAAAA)
	if err != nil || r == nil {
		fmt.Printf("Cannot retrieve AAAA %s: %s\n", qname, err)
		return err
	}
	if r.Rcode == dns.RcodeNameError {
		fmt.Printf("No such domain %s\n", qname)
		return err
	}

	chainOfTrust.aaaaRr = make([]dns.RR, 0, len(r.Answer))

	for _, ans := range r.Answer {
		switch t := ans.(type) {
		case *dns.AAAA:
			chainOfTrust.aaaaRr = append(chainOfTrust.aaaaRr, ans)
			//ips = append(ips, t.AAAA.String())
		case *dns.RRSIG:
			chainOfTrust.aaaaRrsig = t
		}
	}

	// dnssec validation

	fmt.Printf("Chain of trust: \n\nSOA %v\n\nRRSIG %v\n", chainOfTrust.soa, chainOfTrust.soaRrsig)

	// Verify the RRSIG of the requested RRset with the public ZSK.
	if len(chainOfTrust.aRr) > 0 {
		err = chainOfTrust.aRrsig.Verify(validationKeys.zsk, chainOfTrust.aRr)

		if err != nil {
			fmt.Printf("validation A: %s\n", err)
			return err
		}
	}

	if len(chainOfTrust.aaaaRr) > 0 {
		err = chainOfTrust.aaaaRrsig.Verify(validationKeys.zsk, chainOfTrust.aaaaRr)

		if err != nil {
			fmt.Printf("validation AAAA: %s\n", err)
			return err
		}
	}

	if len(chainOfTrust.dnskey) == 0 {
		err = &Error{err: "missing validation DNSKEY"}
		return err
	}
	// Verify the RRSIG of the DNSKEY RRset with the public KSK.
	err = chainOfTrust.dnskeyRrsig.Verify(validationKeys.ksk, chainOfTrust.dnskey)

	if err != nil {
		fmt.Printf("validation DNSKEY: %s\n", err)
		return err
	}

	//if len(chainOfTrust.)

	//7218FDF70DA623B1F83C168CBD0807CE36832A579EF479DD47308C5F
	ds := strings.ToUpper(validationKeys.ksk.ToDS(dns.SHA256).Digest)
	parentDs := strings.ToUpper(chainOfTrust.ds[0].Digest)
	////fmt.Println(ds)
	if parentDs != ds {
		err = &Error{err: "Invalid DS"}
		return err
	}

	return nil
}
