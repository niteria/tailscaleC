// Integration test against the unmodified upstream wireguard-go device.
// No TUN device, elevated privileges, or external network service is required.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

const messageCount = 32

func checksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet))
		packet = packet[2:]
	}
	if len(packet) > 0 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func ipPacket(sequence int, fromC bool) []byte {
	payloadLength := 29 + (sequence%5)*127
	packet := make([]byte, 28+payloadLength)
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[12:], []byte{100, 64, 0, 2, 100, 64, 0, 1})
	binary.BigEndian.PutUint16(packet[20:], 10002)
	binary.BigEndian.PutUint16(packet[22:], 10001)
	packet[28] = 'G'
	if fromC {
		packet[15], packet[19], packet[28] = 1, 2, 'C'
		binary.BigEndian.PutUint16(packet[20:], 10001)
		binary.BigEndian.PutUint16(packet[22:], 10002)
	}
	binary.BigEndian.PutUint16(packet[10:], checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[24:], uint16(8+payloadLength))
	packet[29] = byte(sequence)
	for i := 2; i < payloadLength; i++ {
		packet[28+i] = byte(sequence*17 + i*31)
	}
	return packet
}

func runCase(peerPath string, cInitiates, usePSK bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, peerPath)
	stdin, err := child.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		return err
	}
	childWaited := false
	defer func() {
		if !childWaited {
			cancel()
			_ = child.Wait()
			if stderr.Len() > 0 {
				fmt.Fprint(os.Stderr, stderr.String())
			}
		}
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		return fmt.Errorf("C peer did not announce endpoint: %v", scanner.Err())
	}
	fields := strings.Fields(scanner.Text())
	if len(fields) != 3 || fields[0] != "READY" {
		return fmt.Errorf("invalid C peer announcement: %q", scanner.Text())
	}
	cPort, err := strconv.Atoi(fields[1])
	if err != nil || cPort < 1 || cPort > 65535 || len(fields[2]) != 64 {
		return fmt.Errorf("invalid C endpoint/key: %q", scanner.Text())
	}
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return err
	}
	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	var psk [32]byte
	if usePSK {
		if _, err := rand.Read(psk[:]); err != nil {
			return err
		}
	}
	channel := tuntest.NewChannelTUN()
	dev := device.NewDevice(channel.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard-go: "))
	defer dev.Close()
	configuration := fmt.Sprintf("private_key=%x\nlisten_port=0\nreplace_peers=true\npublic_key=%s\npreshared_key=%x\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=100.64.0.1/32\nendpoint=127.0.0.1:%d\n", privateKey, fields[2], psk, cPort)
	if err := dev.IpcSet(configuration); err != nil {
		return fmt.Errorf("configure upstream device: %w", err)
	}
	if err := dev.Up(); err != nil {
		return err
	}
	state, err := dev.IpcGet()
	if err != nil {
		return err
	}
	goPort := ""
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			goPort = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if goPort == "" || goPort == "0" {
		return fmt.Errorf("upstream device has no listening port")
	}
	initiate := 0
	if cInitiates {
		initiate = 1
	}
	if _, err := fmt.Fprintf(stdin, "%s %s %x %d\n", goPort, hex.EncodeToString(publicKey), psk, initiate); err != nil {
		return err
	}
	_ = stdin.Close()
	// Injecting an outgoing IP packet lets upstream initiate a real Noise
	// handshake when the C peer is configured as the responder.
	send := func(sequence int) error {
		select {
		case channel.Outbound <- ipPacket(sequence, false):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	sent := 0
	if !cInitiates {
		if err := send(0); err != nil {
			return err
		}
		sent = 1
	}
	seen := make([]bool, messageCount)
	for count := 0; count < messageCount; count++ {
		select {
		case packet, ok := <-channel.Inbound:
			if !ok || len(packet) < 30 {
				return fmt.Errorf("invalid upstream TUN packet (%d bytes)", len(packet))
			}
			sequence := int(packet[29])
			if sequence >= messageCount || seen[sequence] || !bytes.Equal(packet, ipPacket(sequence, true)) {
				return fmt.Errorf("C-to-Go packet %d failed byte comparison", sequence)
			}
			seen[sequence] = true
			if sent < messageCount {
				if err := send(sent); err != nil {
					return err
				}
				sent++
			}
		case <-ctx.Done():
			return fmt.Errorf("waiting for C-to-Go payload %d: %w", count, ctx.Err())
		}
	}
	if !scanner.Scan() || scanner.Text() != fmt.Sprintf("PASS tx=%d rx=%d", messageCount, messageCount) {
		return fmt.Errorf("C peer did not confirm bidirectional traffic: %q", scanner.Text())
	}
	err = child.Wait()
	childWaited = true
	if err != nil {
		return fmt.Errorf("C peer: %w: %s", err, stderr.String())
	}
	fmt.Printf("PASS upstream wireguard-go: C initiates=%t PSK=%t, %d payloads each direction\n", cInitiates, usePSK, messageCount)
	return nil
}

func main() {
	peerPath := flag.String("peer", "", "path to the compiled test-wireguard-peer helper")
	flag.Parse()
	if *peerPath == "" {
		fmt.Fprintln(os.Stderr, "-peer must name the compiled C helper")
		os.Exit(2)
	}
	for _, psk := range []bool{false, true} {
		for _, initiates := range []bool{true, false} {
			if err := runCase(*peerPath, initiates, psk); err != nil {
				fmt.Fprintf(os.Stderr, "FAIL C initiates=%t PSK=%t: %v\n", initiates, psk, err)
				os.Exit(1)
			}
		}
	}
}
