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

var syscallNames = map[uint64]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	15:  "rt_sigreturn",
	16:  "ioctl",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	22:  "pipe",
	23:  "select",
	24:  "sched_yield",
	25:  "mremap",
	26:  "msync",
	27:  "mincore",
	28:  "madvise",
	29:  "shmget",
	30:  "shmat",
	31:  "shmctl",
	32:  "dup",
	33:  "dup2",
	34:  "pause",
	35:  "nanosleep",
	36:  "getitimer",
	37:  "alarm",
	38:  "setitimer",
	39:  "getpid",
	40:  "sendfile",
	41:  "socket",
	42:  "connect",
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	48:  "shutdown",
	49:  "bind",
	50:  "listen",
	51:  "getsockname",
	52:  "getpeername",
	53:  "socketpair",
	54:  "setsockopt",
	55:  "getsockopt",
	56:  "clone",
	57:  "fork",
	58:  "vfork",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	63:  "uname",
	64:  "semget",
	65:  "semop",
	66:  "semctl",
	67:  "shmdt",
	68:  "msgget",
	69:  "msgsnd",
	70:  "msgrcv",
	71:  "msgctl",
	72:  "fcntl",
	73:  "flock",
	74:  "fsync",
	75:  "fdatasync",
	76:  "truncate",
	77:  "ftruncate",
	78:  "getdents",
	79:  "getcwd",
	80:  "chdir",
	81:  "fchdir",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	85:  "creat",
	86:  "link",
	87:  "unlink",
	88:  "symlink",
	89:  "readlink",
	90:  "chmod",
	91:  "fchmod",
	92:  "chown",
	93:  "fchown",
	94:  "lchown",
	95:  "umask",
	96:  "gettimeofday",
	97:  "getrlimit",
	98:  "getrusage",
	99:  "sysinfo",
	100: "times",
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu -I/usr/include" bpf ../../pkg/bpf/tracer.c -- -I../../pkg/bpf

type Event struct {
	PID       uint32
	PPID      uint32
	Timestamp uint64
	SyscallID uint64
	Comm      [16]byte
}

func main() {
	var targetPID int
	flag.IntVar(&targetPID, "pid", 0, "Target PID to trace (0 for all processes)")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove rlimit: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	// If PID is specified, update the target PID map
	if targetPID > 0 {
		fmt.Printf("Tracing PID: %d\n", targetPID)
		if err := objs.TargetPidMap.Put(uint32(0), uint32(targetPID)); err != nil {
			log.Fatalf("Failed to update target PID map: %v", err)
		}
	}

	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.HandleSysEnter, nil)
	if err != nil {
		log.Fatalf("Opening tracepoint: %v", err)
	}
	defer tp.Close()

	// Verify BPF program is loaded
	info, err := objs.HandleSysEnter.Info()
	if err != nil {
		log.Fatalf("Getting BPF program info: %v", err)
	}
	fmt.Printf("BPF program loaded: %s\n", info.Name)
	fmt.Printf("BPF program type: %s\n", info.Type)

	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*16)
	if err != nil {
		log.Fatalf("Creating perf event reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Tracing all processes... Hit Ctrl-C to end.")
	fmt.Printf("Using tracepoint: raw_syscalls:sys_enter\n")
	fmt.Printf("Perf buffer size: %d bytes\n", os.Getpagesize()*16)
	fmt.Printf("Starting event processing loop...\n")

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

			if len(record.RawSample) == 0 {
				fmt.Println("Received empty perf event")
				continue
			}

			fmt.Printf("Received perf event, size: %d bytes\n", len(record.RawSample))
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Parsing perf event: %v", err)
				fmt.Printf("Raw sample data: %x\n", record.RawSample)
				continue
			}
			fmt.Printf("Successfully parsed event\n")

			timestamp := time.Unix(0, int64(event.Timestamp))

			comm := make([]byte, 0, 16)
			for _, b := range event.Comm {
				if b == 0 {
					break
				}
				comm = append(comm, b)
			}

			syscallName := syscallNames[event.SyscallID]
			if syscallName == "" {
				syscallName = fmt.Sprintf("unknown(%d)", event.SyscallID)
			}

			fmt.Printf("[%s] PID: %d, PPID: %d, Command: %s, Syscall: %s\n",
				timestamp.Format(time.RFC3339),
				event.PID,
				event.PPID,
				string(comm),
				syscallName,
			)
		}
	}()

	<-sig
	fmt.Println("\nReceived signal, exiting...")
}
