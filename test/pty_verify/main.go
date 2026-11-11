package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: pty_verify <ws_url> <user:pass> <command>\n")
		os.Exit(1)
	}
	wsURL := os.Args[1]
	userPass := os.Args[2]
	cmdStr := os.Args[3]

	headers := http.Header{}
	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(userPass)))

	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial error: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","rows":24,"cols":80}`))
	time.Sleep(150 * time.Millisecond)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(cmdStr+"\n")); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		os.Exit(1)
	}

	var out strings.Builder
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		out.Write(msg)
		if strings.Contains(out.String(), "root") {
			break
		}
	}

	fmt.Print(out.String())
}
