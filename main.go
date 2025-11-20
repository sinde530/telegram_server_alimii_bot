// telegram_guard.go
//
// Usage:
//   Build:   GOOS=linux GOARCH=amd64 go build -o telegram_guard telegram_guard.go
//   Run:     sudo ./telegram_guard -token YOUR_BOT_TOKEN -chat YOUR_CHAT_ID
//   Or set env: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
//
// Note:
//   - This program needs permission to read /var/log/auth.log (run as root or give read access).
//   - Install as systemd service (instructions below) so it starts at boot and receives signals on shutdown.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var (
	botToken string
	chatID   string
	logPath  = "/var/log/auth.log" // Debian/Ubuntu default. Change to /var/log/secure for RHEL/CentOS.
	// Regexes to parse auth.log lines
	reFailed   = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+)`)
	reAccepted = regexp.MustCompile(`Accepted (?:password|publickey|keyboard-interactive) for (\S+) from (\S+)`)
)

func sendTelegram(token, chat, text string) error {
	if token == "" || chat == "" {
		return fmt.Errorf("missing token/chat")
	}
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	form := url.Values{}
	form.Add("chat_id", chat)
	form.Add("text", text)
	// disable web page preview and allow markdown-like text as plain text
	form.Add("disable_web_page_preview", "true")

	resp, err := http.PostForm(api, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// optional: read response body for errors
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram api error: %s - %s", resp.Status, string(body))
	}
	return nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func sendBootNotification() {
	msg := fmt.Sprintf("🚀 서버 부팅: %s\nHost: %s\nOS: %s/%s\nTime: %s",
		hostname(), hostname(), runtime.GOOS, runtime.GOARCH, time.Now().Format(time.RFC1123))
	if err := sendTelegram(botToken, chatID, msg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to send boot notification: %v\n", err)
	} else {
		fmt.Println("sent boot notification")
	}
}

func sendShutdownNotification(sig os.Signal) {
	msg := fmt.Sprintf("⚠️ 서버 종료 신호(%s) 수신: %s\nHost: %s\nTime: %s",
		sig.String(), hostname(), hostname(), time.Now().Format(time.RFC1123))
	if err := sendTelegram(botToken, chatID, msg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to send shutdown notification: %v\n", err)
	} else {
		fmt.Println("sent shutdown notification")
	}
}

// tailAuthLog monitors auth log and sends telegram messages on matched patterns.
// It handles log rotation by reopening file when inode changes.
func tailAuthLog(path string, stop <-chan struct{}) {
	var file *os.File
	var reader *bufio.Reader
	var lastIno uint64

	openFile := func() error {
		if file != nil {
			file.Close()
			file = nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				lastIno = st.Ino
			}
		}
		// seek to end to only receive new entries
		_, _ = f.Seek(0, io.SeekEnd)
		file = f
		reader = bufio.NewReader(f)
		return nil
	}

	if err := openFile(); err != nil {
		fmt.Fprintf(os.Stderr, "cannot open log file %s: %v\n", path, err)
		// retry loop until stop
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Second):
				if err := openFile(); err == nil {
					break
				}
			}
			if file != nil {
				break
			}
		}
	}

	for {
		select {
		case <-stop:
			if file != nil {
				file.Close()
			}
			return
		default:
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					// check for rotation: if inode changed, reopen
					time.Sleep(300 * time.Millisecond)
					info, err2 := os.Stat(path)
					if err2 == nil {
						if st, ok := info.Sys().(*syscall.Stat_t); ok {
							if st.Ino != lastIno {
								// rotated
								fmt.Println("log rotation detected, reopening log file")
								_ = openFile()
							}
						}
					}
					continue
				} else {
					// some error - attempt reopen after delay
					fmt.Fprintf(os.Stderr, "error reading log: %v\n", err)
					time.Sleep(1 * time.Second)
					_ = openFile()
					continue
				}
			}
			processLogLine(string(bytes.TrimSpace(line)))
		}
	}
}

func processLogLine(line string) {
	// quick skip
	if !strings.Contains(line, "sshd") {
		return
	}
	// check failure
	if m := reFailed.FindStringSubmatch(line); m != nil {
		user := m[1]
		ip := m[2]
		msg := fmt.Sprintf("❌ SSH 로그인 실패\nHost: %s\nUser: %s\nFrom: %s\nLine: %s\nTime: %s",
			hostname(), user, ip, truncateLine(line, 200), time.Now().Format(time.RFC3339))
		if err := sendTelegram(botToken, chatID, msg); err != nil {
			fmt.Fprintf(os.Stderr, "failed to send fail alert: %v\n", err)
		} else {
			fmt.Printf("sent fail alert: %s@%s\n", user, ip)
		}
		return
	}
	// check success
	if m := reAccepted.FindStringSubmatch(line); m != nil {
		user := m[1]
		ip := m[2]
		msg := fmt.Sprintf("🔐 SSH 로그인 성공\nHost: %s\nUser: %s\nFrom: %s\nLine: %s\nTime: %s",
			hostname(), user, ip, truncateLine(line, 200), time.Now().Format(time.RFC3339))
		if err := sendTelegram(botToken, chatID, msg); err != nil {
			fmt.Fprintf(os.Stderr, "failed to send success alert: %v\n", err)
		} else {
			fmt.Printf("sent success alert: %s@%s\n", user, ip)
		}
		return
	}
	// other ssh-related events can be extended here
}

func truncateLine(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func main() {
	// flags
	var tokenFlag string
	var chatFlag string
	var logFlag string

	flag.StringVar(&tokenFlag, "token", "", "Telegram bot token (or set TELEGRAM_BOT_TOKEN env)")
	flag.StringVar(&chatFlag, "chat", "", "Telegram chat id (or set TELEGRAM_CHAT_ID env)")
	flag.StringVar(&logFlag, "log", "", "path to auth log (default /var/log/auth.log)")
	flag.Parse()

	// env fallback
	if tokenFlag == "" {
		tokenFlag = os.Getenv("TELEGRAM_BOT_TOKEN")
	}
	if chatFlag == "" {
		chatFlag = os.Getenv("TELEGRAM_CHAT_ID")
	}
	if logFlag != "" {
		logPath = logFlag
	} else {
		// if running on RHEL/CentOS, default /var/log/secure
		if _, err := os.Stat("/var/log/secure"); err == nil && os.Getenv("FORCE_AUTH_LOG") == "" {
			// keep auth.log default unless user overrides with -log
			// but prefer auth.log for Debian; we check existence
			// If auth.log doesn't exist but /var/log/secure exists, use secure.
			if _, err2 := os.Stat("/var/log/auth.log"); os.IsNotExist(err2) {
				logPath = "/var/log/secure"
			}
		}
	}

	if tokenFlag == "" || chatFlag == "" {
		fmt.Fprintln(os.Stderr, "ERROR: Telegram token and chat id must be provided via flags or env variables.")
		flag.Usage()
		os.Exit(2)
	}

	botToken = tokenFlag
	chatID = chatFlag

	fmt.Printf("Starting telegram_guard - host=%s log=%s\n", hostname(), logPath)
	// send boot notification
	sendBootNotification()

	// handle signals for shutdown
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	stop := make(chan struct{})

	go func() {
		// tail the auth log and send alerts
		tailAuthLog(logPath, stop)
	}()

	// wait for signal
	sig := <-sigc
	fmt.Printf("received signal: %v\n", sig)
	// attempt to send shutdown notification (best-effort)
	sendShutdownNotification(sig)
	// stop tailing and exit
	close(stop)
	// small delay to allow message send
	time.Sleep(500 * time.Millisecond)
	fmt.Println("exiting")
}
