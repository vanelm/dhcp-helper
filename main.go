package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var version = "dev"

func main() {
	// Subcommand: stats
	if len(os.Args) > 1 && os.Args[1] == "stats" {
		runStatsClient()
		return
	}

	ifaces := flag.String("i", "", "comma-separated capture interfaces")
	target := flag.String("t", "", "profiler DHCP listener address (host:port)")
	daemon := flag.Bool("d", false, "daemonize")
	debug := flag.Bool("debug", false, "enable debug-level logging (per-packet)")
	sock := flag.String("s", "/var/run/dhcp-helper.sock", "stats unix socket path")
	pidFile := flag.String("p", "/var/run/dhcp-helper.pid", "PID file (daemon mode)")
	logFile := flag.String("l", "/var/log/dhcp-helper.log", "log file (daemon mode)")
	snapLen := flag.Int("snap", 1600, "pcap snapshot length")
	ver := flag.Bool("V", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dhcp-helper -i <ifaces> -t <host:port> [flags]\n")
		fmt.Fprintf(os.Stderr, "       dhcp-helper stats [-s <socket>]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *ver {
		fmt.Println("dhcp-helper", version)
		return
	}
	if *ifaces == "" || *target == "" {
		flag.Usage()
		os.Exit(1)
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	// Daemon: re-exec without -d, redirect output, exit parent
	if *daemon {
		daemonize(*pidFile, *logFile)
		return
	}

	// Write PID file if we're the daemon child
	if pf := os.Getenv("_DHCP_HELPER_PID"); pf != "" {
		_ = os.WriteFile(pf, []byte(strconv.Itoa(os.Getpid())), 0644)
		defer os.Remove(pf)
	}

	run(strings.Split(*ifaces, ","), *target, *sock, int32(*snapLen))
}

func daemonize(pidFile, logPath string) {
	args := make([]string, 0, len(os.Args))
	for _, a := range os.Args[1:] {
		if a != "-d" {
			args = append(args, a)
		}
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open log %s: %v\n", logPath, err)
		os.Exit(1)
	}

	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "_DHCP_HELPER_PID="+pidFile)
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "fork: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("dhcp-helper started (PID %d), log: %s\n", cmd.Process.Pid, logPath)
}

func run(ifaces []string, target, sockPath string, snapLen int32) {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		slog.Error("resolve target", "addr", target, "err", err)
		os.Exit(1)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		slog.Error("dial target", "addr", target, "err", err)
		os.Exit(1)
	}
	defer conn.Close()

	st := newStats()

	go serveStats(sockPath, st)
	defer os.Remove(sockPath)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for _, name := range ifaces {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		wg.Add(1)
		go func(iface string) {
			defer wg.Done()
			capture(stop, iface, snapLen, conn, st)
		}(name)
	}

	slog.Info("dhcp-helper started", "version", version, "interfaces", ifaces, "target", target)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("shutting down")
	close(stop)
	wg.Wait()
}
