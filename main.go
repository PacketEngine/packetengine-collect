package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	ingestURL = "https://collect.packetengine.co.uk/ingest"
)

func main() {
	fmt.Println("[+] Starting packetengine-collect...")

	// Automatically detect the active network interface
	var ifaceName string
	var err error
	if runtime.GOOS == "windows" {
		ifaceName, err = getWindowsActiveInterface()
	} else {
		var iface *net.Interface
		iface, err = getActiveInterface()
		ifaceName = iface.Name
	}

	if err != nil {
		log.Fatal("Error detecting active network interface:", err)
	}
	fmt.Println("[+] Using interface:", ifaceName)

	// Open the device for packet capture
	handle, err := pcap.OpenLive(ifaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err, "\nHint: Make sure you're running as root.")
	}
	defer handle.Close()

	// Define a BPF filter to capture only DNS traffic (port 53)
	err = handle.SetBPFFilter("udp port 53")
	if err != nil {
		log.Fatal(err)
	}

	// Channel for sending DNS answers to a separate goroutine for POSTing
	answersChan := make(chan string, 100)
	var wg sync.WaitGroup

	// Goroutine for handling POST requests concurrently
	go postWorker(answersChan, &wg)

	// Use a set to store unique answer names
	uniqueAnswers := make(map[string]bool)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true // Lazy decoding for better performance

	fmt.Println("[+] Starting DNS capture...")

	for packet := range packetSource.Packets() {
		// Extract DNS layer from the packet
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}

		dns, _ := dnsLayer.(*layers.DNS)

		// Process DNS responses (QR = true)
		if dns.QR {
			for _, answer := range dns.Answers {
				answerName := string(answer.Name)
				if answer.IP.String() != "<nil>" {
					// Check if the answer is already seen
					if _, exists := uniqueAnswers[answerName]; !exists {
						uniqueAnswers[answerName] = true

						// Send the new answer to the answers channel
						answersChan <- answerName
					}
				}
			}
		}
	}

	// Close the answers channel and wait for POST goroutines to finish
	close(answersChan)
	wg.Wait()
}

// Goroutine worker for posting DNS answers to the server
func postWorker(answersChan chan string, wg *sync.WaitGroup) {
	for answer := range answersChan {
		wg.Add(1)
		go func(answer string) {
			defer wg.Done()
			postData := map[string]string{"answer": answer}
			err := postJSON(postData)
			if err != nil {
				log.Println("[!] Error sending DNS answer:", answer, err)
			} else {
				fmt.Println("[+] Successfully sent DNS answer:", answer)
			}
		}(answer)
	}
}

// Function to post data to a URL
func postJSON(data map[string]string) error {
	// Convert data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("[!] error marshalling data to JSON: %v", err)
	}

	// Make POST request
	resp, err := http.Post(ingestURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("[!] error posting data: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("[!] failed to send. Status code: %v", resp.StatusCode)
	}
	return nil
}

// Windows specific active interface detection
func getWindowsActiveInterface() (string, error) {
	// Use pcap.FindAllDevs to list all interfaces
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	for _, device := range devices {
		if len(device.Addresses) > 0 {
			for _, addr := range device.Addresses {
				if addr.IP.To4() != nil { // Return the first device with an IPv4 address
					return device.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("[!] no active network interface found")
}

// Function to get the active network interface for Unix-like systems
func getActiveInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		// Skip interfaces that are down or not flags for multicast/broadcast
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Find interfaces that have an IP address assigned
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil { // IPv4 only
					return &iface, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("[!] no active network interface found")
}
