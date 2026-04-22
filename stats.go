package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ---- Tracking ----

type stats struct {
	mu      sync.RWMutex
	started time.Time
	total   atomic.Uint64
	ifaces  map[string]*ifaceTracker
}

type ifaceTracker struct {
	mu        sync.Mutex
	forwarded uint64
	errors    uint64
	vlans     map[uint16]uint64
	lastSeen  time.Time
}

func newStats() *stats {
	return &stats{started: time.Now(), ifaces: make(map[string]*ifaceTracker)}
}

func (s *stats) tracker(iface string) *ifaceTracker {
	s.mu.RLock()
	t, ok := s.ifaces[iface]
	s.mu.RUnlock()
	if ok {
		return t
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok = s.ifaces[iface]; ok {
		return t
	}
	t = &ifaceTracker{vlans: make(map[uint16]uint64)}
	s.ifaces[iface] = t
	return t
}

func (s *stats) incrForwarded(iface string, vlanID uint16) {
	t := s.tracker(iface)
	t.mu.Lock()
	t.forwarded++
	t.vlans[vlanID]++
	t.lastSeen = time.Now()
	t.mu.Unlock()
	s.total.Add(1)
}

func (s *stats) incrError(iface string) {
	t := s.tracker(iface)
	t.mu.Lock()
	t.errors++
	t.mu.Unlock()
}

// ---- Snapshot for IPC ----

type statsSnapshot struct {
	Uptime     string                    `json:"uptime"`
	Total      uint64                    `json:"total"`
	Interfaces map[string]*ifaceSnapshot `json:"interfaces"`
}

type ifaceSnapshot struct {
	Forwarded uint64            `json:"forwarded"`
	Errors    uint64            `json:"errors"`
	LastSeen  string            `json:"last_seen,omitempty"`
	VLANs     map[uint16]uint64 `json:"vlans"`
}

func (s *stats) snapshot() statsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := statsSnapshot{
		Uptime:     time.Since(s.started).Round(time.Second).String(),
		Total:      s.total.Load(),
		Interfaces: make(map[string]*ifaceSnapshot, len(s.ifaces)),
	}
	for name, t := range s.ifaces {
		t.mu.Lock()
		is := &ifaceSnapshot{
			Forwarded: t.forwarded,
			Errors:    t.errors,
			VLANs:     make(map[uint16]uint64, len(t.vlans)),
		}
		if !t.lastSeen.IsZero() {
			is.LastSeen = t.lastSeen.Format(time.RFC3339)
		}
		for vid, cnt := range t.vlans {
			is.VLANs[vid] = cnt
		}
		t.mu.Unlock()
		snap.Interfaces[name] = is
	}
	return snap
}

// ---- Unix socket IPC server ----

func serveStats(sockPath string, st *stats) {
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Printf("stats socket %s: %v", sockPath, err)
		return
	}
	defer ln.Close()
	os.Chmod(sockPath, 0666)

	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			json.NewEncoder(c).Encode(st.snapshot())
		}(c)
	}
}

// ---- CLI stats client ----

func runStatsClient() {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	sockPath := fs.String("s", "/var/run/dhcp-helper.sock", "stats unix socket path")
	jsonOut := fs.Bool("json", false, "output raw JSON")
	fs.Parse(os.Args[2:])

	c, err := net.DialTimeout("unix", *sockPath, 2*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect %s: %v (is dhcp-helper running?)\n", *sockPath, err)
		os.Exit(1)
	}
	defer c.Close()

	var snap statsSnapshot
	if err := json.NewDecoder(c).Decode(&snap); err != nil {
		fmt.Fprintf(os.Stderr, "decode: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(snap)
		return
	}

	fmt.Printf("Uptime: %s  |  Total forwarded: %d\n\n", snap.Uptime, snap.Total)
	for name, is := range snap.Interfaces {
		fmt.Printf("  %-12s  forwarded=%-8d errors=%-4d", name, is.Forwarded, is.Errors)
		if is.LastSeen != "" {
			fmt.Printf("  last=%s", is.LastSeen)
		}
		fmt.Println()

		if len(is.VLANs) > 0 {
			vids := make([]int, 0, len(is.VLANs))
			for v := range is.VLANs {
				vids = append(vids, int(v))
			}
			sort.Ints(vids)
			for _, v := range vids {
				label := "native"
				if v > 0 {
					label = fmt.Sprintf("VLAN %d", v)
				}
				fmt.Printf("    %-14s %d\n", label, is.VLANs[uint16(v)])
			}
		}
		fmt.Println()
	}
}
