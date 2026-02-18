//go:build linux

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func identifyProcess(remoteAddr string) string {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return ""
	}

	// We only try to identify local processes
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		// Could also check local interface IPs, but let's stick to loopback for now
		// or just try anyway if it's a local-looking IP.
	}

	inode, err := findInode(host, port)
	if err != nil || inode == "" {
		return ""
	}

	pid := findPidByInode(inode)
	if pid == 0 {
		return ""
	}

	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	cmdlineStr := strings.ReplaceAll(string(cmdline), "\x00", " ")
	cmdlineStr = strings.TrimSpace(cmdlineStr)

	if cmdlineStr != "" {
		return fmt.Sprintf("PID:%d [%s]", pid, cmdlineStr)
	}

	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return fmt.Sprintf("PID:%d (%s)", pid, strings.TrimSpace(string(comm)))
}

func findInode(host string, port int) (string, error) {
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	for _, file := range files {
		inode, err := searchInodeInFile(file, host, port)
		if err == nil && inode != "" {
			return inode, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func searchInodeInFile(filename, host string, port int) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Skip header
	if scanner.Scan() {
	}

	hexPort := fmt.Sprintf("%04X", port)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localAddr := fields[1]
		state := fields[3]

		if state != "01" { // ESTABLISHED
			continue
		}

		// localAddr is in format HEXIP:HEXPORT
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		if parts[1] == hexPort {
			// Inode is the 10th field (index 9)
			return fields[9], nil
		}
	}
	return "", nil
}

func findPidByInode(inode string) int {
	pids, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	target := "socket:[" + inode + "]"
	for _, p := range pids {
		if !p.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}

		fdPath := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if err == nil && link == target {
				return pid
			}
		}
	}
	return 0
}
