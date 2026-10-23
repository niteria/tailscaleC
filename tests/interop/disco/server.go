// Independent UDP peer: upstream disco marshalling/parsing and Go NaCl boxes.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"tailscale.com/disco"
	"tailscale.com/types/key"
)

const rounds = 200

func main() {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	node := key.NewNode().Public()
	clientNodePrivate := [32]byte{17, 33, 4, 88, 9}
	clientNodePublic, err := curve25519.X25519(clientNodePrivate[:], curve25519.Basepoint)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"address": conn.LocalAddr().String(), "node_key": node.UntypedHexString(),
		"disco_key": hex.EncodeToString(public[:]), "rounds": rounds,
		"upstream": "tailscale.com v1.102.3 disco + golang.org/x/crypto/nacl/box",
	}); err != nil {
		log.Fatal(err)
	}
	buffer := make([]byte, 2048)
	awaiting := map[[12]byte]netip.AddrPort{}
	receivedPings, receivedPongs := 0, 0
	send := func(to netip.AddrPort, recipient *[32]byte, message disco.Message) {
		var nonce [24]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			log.Fatal(err)
		}
		packet := append([]byte(disco.Magic), public[:]...)
		packet = append(packet, nonce[:]...)
		packet = box.Seal(packet, message.AppendMarshal(nil), &nonce, recipient, private)
		if _, err := conn.WriteToUDPAddrPort(packet, to); err != nil {
			log.Fatal(err)
		}
	}
	for receivedPongs < rounds {
		n, from, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			log.Fatal(err)
		}
		if !disco.LooksLikeDiscoWrapper(buffer[:n]) || n < 78 {
			log.Fatal("invalid DISCO wrapper")
		}
		var sender [32]byte
		var nonce [24]byte
		copy(sender[:], buffer[6:38])
		copy(nonce[:], buffer[38:62])
		plain, ok := box.Open(nil, buffer[62:n], &nonce, &sender, private)
		if !ok {
			log.Fatal("C NaCl authentication failed")
		}
		message, err := disco.Parse(plain)
		if err != nil {
			log.Fatal(err)
		}
		switch m := message.(type) {
		case *disco.Ping:
			if m.NodeKey.UntypedHexString() != hex.EncodeToString(clientNodePublic) {
				log.Fatal("C ping node key mismatch")
			}
			receivedPings++
			send(from, &sender, &disco.Pong{TxID: m.TxID, Src: from})
			var txid [12]byte
			if _, err := rand.Read(txid[:]); err != nil {
				log.Fatal(err)
			}
			awaiting[txid] = from
			send(from, &sender, &disco.Ping{TxID: txid, NodeKey: node})
		case *disco.Pong:
			expected, exists := awaiting[m.TxID]
			if !exists || expected != from {
				log.Fatal("unexpected C pong transaction/source")
			}
			if m.Src != conn.LocalAddr().(*net.UDPAddr).AddrPort() {
				log.Fatal("C pong observed endpoint mismatch")
			}
			delete(awaiting, m.TxID)
			receivedPongs++
		default:
			log.Fatalf("unexpected C message %T", message)
		}
	}
	if receivedPings != rounds || len(awaiting) != 0 {
		log.Fatal("incomplete DISCO exchange")
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"passed": true, "c_pings": receivedPings, "c_pongs": receivedPongs,
	}); err != nil {
		log.Fatal(err)
	}
}
