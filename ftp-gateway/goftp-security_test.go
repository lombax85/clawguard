package server

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"goftp.io/server/v2/ratelimit"
)

func TestClawGuardDisablesActiveModeCommands(t *testing.T) {
	for _, command := range []string{"PORT", "EPRT", "LPRT"} {
		if _, enabled := defaultCommands[command]; enabled {
			t.Fatalf("active-mode command %s must not be enabled", command)
		}
	}
	for _, command := range []string{"PASV", "EPSV", "LIST", "RETR"} {
		if _, enabled := defaultCommands[command]; !enabled {
			t.Fatalf("passive/read command %s must remain enabled", command)
		}
	}
}

func TestClawGuardPassivePeerUsesNormalizedControlIP(t *testing.T) {
	control := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 12345}
	mapped := &net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.10"), Port: 54321}
	attacker := &net.TCPAddr{IP: net.ParseIP("192.0.2.11"), Port: 54321}
	if !sameTCPPeerIP(control, mapped) {
		t.Fatal("IPv4 and its IPv4-mapped IPv6 form must identify the same peer")
	}
	if sameTCPPeerIP(control, attacker) {
		t.Fatal("a passive data peer from another IP must be rejected")
	}
	if sameTCPPeerIP(control, &net.UnixAddr{Name: "unexpected", Net: "unix"}) {
		t.Fatal("an unexpected address type must fail closed")
	}
}

func TestClawGuardPassiveListenerRejectsDifferentSourceBeforeLegitimatePeer(t *testing.T) {
	controlListener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer controlListener.Close()
	acceptedControl := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := controlListener.Accept()
		if acceptErr == nil {
			acceptedControl <- conn
		}
	}()
	controlClient, err := net.Dial("tcp6", controlListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer controlClient.Close()
	controlServer := <-acceptedControl
	defer controlServer.Close()

	sess := &Session{
		conn:   controlServer,
		server: &Server{rateLimiter: ratelimit.New(0)},
	}
	socket := &passiveSocket{sess: sess}
	if err := socket.ListenAndServe(); err != nil {
		t.Fatal(err)
	}

	attacker, err := net.DialTimeout(
		"tcp4",
		net.JoinHostPort("127.0.0.1", stringPort(socket.port)),
		time.Second,
	)
	if err == nil {
		defer attacker.Close()
		_ = attacker.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := attacker.Read(make([]byte, 1)); err == nil {
			t.Fatal("different-source passive peer remained connected")
		} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Fatal("different-source passive peer was not promptly rejected")
		} else if err != io.EOF {
			// A reset is also a valid fail-closed rejection.
			t.Logf("different-source peer rejected with %v", err)
		}
	}

	legitimate, err := net.DialTimeout(
		"tcp6",
		net.JoinHostPort("::1", stringPort(socket.port)),
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer legitimate.Close()

	socket.lock.Lock()
	defer socket.lock.Unlock()
	if socket.conn == nil || !sameTCPPeerIP(controlServer.RemoteAddr(), socket.conn.RemoteAddr()) {
		t.Fatal("legitimate control peer was not adopted as the passive data peer")
	}
}

func stringPort(port int) string {
	return strconv.Itoa(port)
}

func TestClawGuardControlConnectionLimitIsBounded(t *testing.T) {
	if maxConcurrentControlConnections < 2 || maxConcurrentControlConnections > 16 {
		t.Fatalf("unexpected control connection bound: %d", maxConcurrentControlConnections)
	}
}

func TestClawGuardRejectsOversizedControlCommand(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	server := &Server{
		Options: &Options{WelcomeMessage: "test", Logger: &DiscardLogger{}},
		logger:  &DiscardLogger{},
	}
	session := server.newSession("bounded-line", serverConn)
	done := make(chan struct{})
	go func() {
		session.Serve()
		close(done)
	}()

	reader := bufio.NewReader(clientConn)
	if welcome, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(welcome, "220 ") {
		t.Fatalf("unexpected welcome response %q: %v", welcome, err)
	}
	writeDone := make(chan struct{})
	go func() {
		_, _ = clientConn.Write(bytes.Repeat([]byte{'A'}, 8192))
		close(writeDone)
	}()
	if response, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(response, "500 ") {
		t.Fatalf("oversized command was not rejected: %q, %v", response, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session remained alive after an oversized command")
	}
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("oversized writer remained blocked after session close")
	}
}
