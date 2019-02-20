// Copyright (c) 2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/decred/dcrseeder/dnssec"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/decred/dcrd/wire"
	"github.com/miekg/dns"
)

type DNSServer struct {
	hostname   string
	listen     string
	nameserver string
}

func (d *DNSServer) Start() {
	defer wg.Done()

	rr := fmt.Sprintf("%s 86400 IN NS %s", d.hostname, d.nameserver)
	authority, err := dns.NewRR(rr)
	if err != nil {
		log.Printf("NewRR: %v", err)
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp4", d.listen)
	if err != nil {
		log.Printf("ResolveUDPAddr: %v", err)
		return
	}

	udpListen, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("ListenUDP: %v", err)
		return
	}
	defer udpListen.Close()

	for {
		b := make([]byte, 512)
		_, addr, err := udpListen.ReadFromUDP(b)
		if err != nil {
			log.Printf("Read: %v", err)
			continue
		}

		go func() {
			dnsMsg := new(dns.Msg)
			err = dnsMsg.Unpack(b[:])
			if err != nil {
				log.Printf("%s: invalid dns message: %v",
					addr, err)
				return
			}
			if len(dnsMsg.Question) != 1 {
				log.Printf("%s sent more than 1 question: %d",
					addr, len(dnsMsg.Question))
				return
			}
			domainName := strings.ToLower(dnsMsg.Question[0].Name)

			// TODO respond back with proper NXDOMAIN
			//ff := strings.LastIndex(domainName, d.hostname)
			//if ff < 0 {
			//	log.Printf("invalid name: %s",
			//		dnsMsg.Question[0].Name)
			//	return
			//}

			wantedSF := wire.SFNodeNetwork
			labels := dns.SplitDomainName(domainName)
			if labels[0][0] == 'x' && len(labels[0]) > 1 {
				wantedSFStr := labels[0][1:]
				u, err := strconv.ParseUint(wantedSFStr, 10, 64)
				if err != nil {
					log.Printf("%s: ParseUint: %v", addr, err)
					return
				}
				wantedSF = wire.ServiceFlag(u)
			}

			respMsg := dnsMsg.Copy()
			respMsg.Authoritative = true
			respMsg.Response = true

			log.Printf("%s: query %d for %v", addr,
				dnsMsg.Question[0].Qtype, wantedSF)

			aResponse := func(qtype uint16, atype string) {
				respMsg.Ns = append(respMsg.Ns, authority)
				respMsg.Ns, err = dnssec.SignRRSet(respMsg.Ns)
				if err == nil {
					log.Printf("unable to sign %s response", atype)
				}
				ips := amgr.GoodAddresses(qtype, wantedSF)
				for _, ip := range ips {
					rr = fmt.Sprintf("%s 30 IN %s %s",
						dnsMsg.Question[0].Name, atype,
						ip.String())
					newRR, err := dns.NewRR(rr)
					if err != nil {
						log.Printf("%s: NewRR: %v",
							addr, err)
						return
					}
					respMsg.Answer = append(respMsg.Answer, newRR)
				}

				if respMsg.Answer != nil {
					respMsg.Answer, err = dnssec.SignRRSet(respMsg.Answer)
					if err != nil {
						log.Printf("DNSSEC: cannot sign %s RR: %v", atype, err)
						return
					}
				}
			}

			var atype string
			qtype := dnsMsg.Question[0].Qtype
			switch qtype {
			case dns.TypeA:
				atype = "A"
				aResponse(qtype, atype)

			case dns.TypeAAAA:
				atype = "AAAA"
				aResponse(qtype, atype)

			case dns.TypeNS:
				atype = "NS"
				rr = fmt.Sprintf("%s 86400 IN NS %s",
					dnsMsg.Question[0].Name, d.nameserver)
				newRR, err := dns.NewRR(rr)
				if err != nil {
					log.Printf("%s: NewRR: %v", addr, err)
					return
				}
				respMsg.Answer = append(respMsg.Answer, newRR)
				respMsg.Answer, err = dnssec.SignRRSet(respMsg.Answer)

			case dns.TypeDNSKEY:
				atype = "DNSKEY"
				rrSet, rrSig, err := dnssec.GetSignedDNSKEY()
				if err != nil {
					return
				}
				respMsg.Answer = append(respMsg.Answer, rrSet[0], rrSet[1], rrSig)

			case dns.TypeSOA:
				atype = "SOA"
				soa := new(dns.SOA)
				soa.Hdr = dns.RR_Header{d.hostname, dns.TypeSOA, dns.ClassINET, 14400, 0}
				soa.Ns = "seed.stakey.org."
				soa.Mbox = "hostmaster.stakey.org."
				soa.Serial = 1164162633
				soa.Refresh = 3600
				soa.Retry = 900
				soa.Expire = 1209600
				soa.Minttl = 86400
				respMsg.Answer = append(respMsg.Answer, soa)
				respMsg.Answer, err = dnssec.SignRRSet(respMsg.Answer)
				if err != nil {
					return
				}

			case dns.TypeDS:

			default:
				log.Printf("%s: invalid qtype: %d", addr, dnsMsg.Question[0].Qtype)
				return
			}

			//done:
			sendBytes, err := respMsg.Pack()
			if err != nil {
				log.Printf("%s: failed to pack response: %v",
					addr, err)
				return
			}

			_, err = udpListen.WriteToUDP(sendBytes, addr)
			if err != nil {
				log.Printf("%s: failed to write response: %v",
					addr, err)
				return
			}
		}()
	}
}

func NewDNSServer(hostname, nameserver, listen string) *DNSServer {
	if hostname[len(hostname)-1] != '.' {
		hostname = hostname + "."
	}
	if nameserver[len(nameserver)-1] != '.' {
		nameserver = nameserver + "."
	}

	return &DNSServer{
		hostname:   hostname,
		listen:     listen,
		nameserver: nameserver,
	}
}
