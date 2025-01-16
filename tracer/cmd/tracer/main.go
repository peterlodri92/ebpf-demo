package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu -I/usr/include" bpf ../../pkg/bpf/tracer.c -- -I../../pkg/bpf

type Event struct {
	PID       uint32
	PPID      uint32
	Timestamp uint64
	Comm      [16]byte
}

func main() {
	var targetPid int
	flag.IntVar(&targetPid, "pid", 0, "Process ID to trace")
	flag.Parse()

	if targetPid == 0 {
		log.Fatal("Please specify a PID to trace with -pid")
	}

	if _, err := os.FindProcess(targetPid); err != nil {
		log.Fatalf("Process %d not found: %v", targetPid, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	if err := objs.TargetPidMap.Put(uint32(0), uint32(targetPid)); err != nil {
		log.Fatalf("Failed to set target PID: %v", err)
	}

	execTP, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExec, nil)
	if err != nil {
		log.Fatalf("Opening exec tracepoint: %v", err)
	}
	defer execTP.Close()

	exitTP, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		log.Fatalf("Opening exit tracepoint: %v", err)
	}
	defer exitTP.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf event reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("Tracing PID %d... Hit Ctrl-C to end.\n", targetPid)

	go func() {
		var event Event
		for {
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				log.Printf("Reading perf event: %v", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("Lost %d samples", record.LostSamples)
				continue
			}

			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Parsing perf event: %v", err)
				continue
			}

			timestamp := time.Unix(0, int64(event.Timestamp))

			comm := make([]byte, 0, 16)
			for _, b := range event.Comm {
				if b == 0 {
					break
				}
				comm = append(comm, b)
			}

			fmt.Printf("[%s] PID: %d, PPID: %d, Command: %s\n",
				timestamp.Format(time.RFC3339),
				event.PID,
				event.PPID,
				string(comm),
			)
		}
	}()

	<-sig
	fmt.Println("\nReceived signal, exiting...")
}
