// Local-only interoperability fixture using unmodified upstream DERP code.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	s := derpserver.New(key.NewNode(), logger.Discard)
	defer s.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	httpServer := &http.Server{Handler: derpserver.Handler(s), ReadHeaderTimeout: 5 * time.Second}
	defer httpServer.Close()
	go func() { _ = httpServer.Serve(listener) }()

	// The reference peer itself uses the upstream Go DERP client, rather than
	// reproducing C framing in a second language.
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	fmt.Fprintf(writer, "GET /derp HTTP/1.1\r\nHost: %s\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n", listener.Addr())
	if err := writer.Flush(); err != nil {
		log.Fatal(err)
	}
	resp, err := http.ReadResponse(reader, nil)
	if err != nil || resp.StatusCode != 101 {
		log.Fatalf("HTTP upgrade: response=%v error=%v", resp, err)
	}
	peer, err := derp.NewClient(key.NewNode(), conn, bufio.NewReadWriter(reader, writer), logger.Discard, derp.CanAckPings(true))
	if err != nil {
		log.Fatal(err)
	}
	// Read the authenticated ServerInfo so registration is complete before the
	// C side can send a packet to this public key.
	if _, err := peer.Recv(); err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{
		"address": listener.Addr().String(), "peer_key": peer.PublicKey().UntypedHexString(),
		"upstream": "tailscale.com v1.102.3",
	}); err != nil {
		log.Fatal(err)
	}
	for {
		message, err := peer.Recv()
		if err != nil {
			log.Fatal(err)
		}
		switch m := message.(type) {
		case derp.ReceivedPacket:
			if err := peer.Send(m.Source, m.Data); err != nil {
				log.Fatal(err)
			}
		case derp.PingMessage:
			if err := peer.SendPong([8]byte(m)); err != nil {
				log.Fatal(err)
			}
		}
	}
}
