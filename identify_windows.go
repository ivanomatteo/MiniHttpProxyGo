//go:build windows

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func identifyProcess(remoteAddr string) string {
	_, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}

	// Run netstat -ano to find the PID
	// We look for a line that has the port in the local address column
	cmd := exec.Command("netstat", "-ano", "-p", "tcp")
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return ""
	}

	scanner := bufio.NewScanner(&out)
	targetPort := ":" + portStr
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// TCP    127.0.0.1:51234    127.0.0.1:3128    ESTABLISHED    1234
		localAddr := fields[1]
		if strings.HasSuffix(localAddr, targetPort) {
			pidStr := fields[len(fields)-1]
			pid, _ := strconv.Atoi(pidStr)
			if pid > 0 {
				name := getProcessName(pidStr)
				cmdline := getProcessCommandLine(pidStr)

				if cmdline != "" {
					return fmt.Sprintf("PID:%d [%s]", pid, cmdline)
				}
				if name != "" {
					return fmt.Sprintf("PID:%d (%s)", pid, name)
				}
				return fmt.Sprintf("PID:%d", pid)
			}
		}
	}

	return ""
}

func getProcessCommandLine(pid string) string {
	// wmic process where processid=1234 get commandline /format:list
	cmd := exec.Command("wmic", "process", "where", "processid="+pid, "get", "commandline", "/format:list")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return ""
	}

	// Output format:
	//
	// CommandLine=...
	//
	//
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "CommandLine=") {
			return strings.TrimPrefix(line, "CommandLine=")
		}
	}
	return ""
}

func getProcessName(pid string) string {
	// tasklist /FI "PID eq 1234" /NH /FO CSV
	cmd := exec.Command("tasklist", "/FI", "PID eq "+pid, "/NH", "/FO", "CSV")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return ""
	}

	// Output format: "name","pid","session name","session#","mem"
	line := out.String()
	parts := strings.Split(line, ",")
	if len(parts) > 0 {
		name := strings.Trim(parts[0], "\"")
		return name
	}
	return ""
}
