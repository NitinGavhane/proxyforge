// Command wsecho is a tiny WebSocket echo server/client used to demo
// ProxyForge's WebSocket capture. Run the server, point a client at it
// through the proxy, and watch the frames appear in the UI.
//
//	go run ./demos/wsecho -mode server -addr 127.0.0.1:19002
//	go run ./demos/wsecho -mode client -url ws://127.0.0.1:19002/chat \
//	    -proxy http://127.0.0.1:8080 [-count 5]
package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	mode := flag.String("mode", "server", "server | client")
	addr := flag.String("addr", "127.0.0.1:19002", "server listen addr")
	wsURL := flag.String("url", "ws://127.0.0.1:19002/chat", "client target url")
	proxy := flag.String("proxy", "", "client proxy url (http://host:port)")
	count := flag.Int("count", 5, "client messages before closing")
	flag.Parse()

	switch *mode {
	case "server":
		server(*addr)
	case "client":
		if err := client(*wsURL, *proxy, *count); err != nil {
			fmt.Fprintln(os.Stderr, "client:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "mode must be server or client")
		os.Exit(2)
	}
}

func server(addr string) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	http.HandleFunc("/chat", func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if err := c.WriteMessage(mt, append([]byte("echo: "), msg...)); err != nil {
				return
			}
		}
	})
	fmt.Println("wsecho listening on", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func client(rawURL, proxy string, count int) error {
	d := &websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return err
		}
		d.Proxy = http.ProxyURL(u)
	}
	c, resp, err := d.Dial(rawURL, nil)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial: %v (status %d)", err, resp.StatusCode)
		}
		return err
	}
	defer c.Close()
	for i := 1; i <= count; i++ {
		msg := fmt.Sprintf("message-%d", i)
		if err := c.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			return err
		}
		_, got, err := c.ReadMessage()
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", got)
	}
	_ = c.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"),
		time.Now().Add(time.Second))
	fmt.Println("client finished")
	return nil
}
