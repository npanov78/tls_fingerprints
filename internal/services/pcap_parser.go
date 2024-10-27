package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dreadl0ck/ja3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

// TLSHandshake структура пакета
type TLSHandshake struct {
	ID           int            `json:"id"`
	SrcIp        string         `json:"src_ip"`
	DstIp        string         `json:"dst_ip"`
	SrcPort      string         `json:"src_port"`
	DstPort      string         `json:"dst_port"`
	Fingerprints JAFingerprints `json:"fingerprints"`
}

// JAFingerprints структура с 4 типами цифровых отпечатков TLS
type JAFingerprints struct {
	JA3      string `json:"ja3,omitempty"`
	JA3byte  string `json:"ja3_byte,omitempty"`
	JA3s     string `json:"ja3s,omitempty"`
	JA3sbyte string `json:"ja3s_byte,omitempty"`
}

// ProcessPCAP обрабатывает дамп трафика и пишет результат отпечатков в JSON
func ProcessPCAP(path string, wg *sync.WaitGroup) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	handshakes, err := parseTLSPackets(handle)
	if err != nil {
		log.Fatal(err)
	}

	err = saveHandshakes(handshakes, path)
	if err != nil {
		log.Fatal(err)
	}
	wg.Done()
}

// parseTLSPackets обрабатывает пакеты TLS в дампе
func parseTLSPackets(handle *pcap.Handle) ([]TLSHandshake, error) {
	// слайс для хранения данных TLS
	var handshakes []TLSHandshake
	id := 0

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		err := calculateFingerprints(packet, &handshakes, &id)
		if err != nil {
			continue
		}
	}

	return handshakes, nil
}

// calculateFingerprints вычисляет цифровые отпечатки для нужных пакетов
func calculateFingerprints(packet gopacket.Packet, handshakes *[]TLSHandshake, id *int) error {
	// Извлечение IP слоя
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return errors.New("no IP layer")
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Извлечение TCP слоя
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return errors.New("no TCP layer")
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	tlsPayload := tcp.Payload

	if len(tlsPayload) > 0 && tlsPayload[0] == 0x16 { // Content Type: Handshake
		ja3Hex := ja3.BarePacket(packet) // Получаем строку JA3 для ClientHello

		if tlsPayload[5] == 0x01 { // Client Hello
			ja3Str := string(ja3Hex)
			*handshakes = append(*handshakes, TLSHandshake{
				ID:      *id,
				SrcIp:   ip.SrcIP.String(),
				DstIp:   ip.DstIP.String(),
				SrcPort: strconv.Itoa(int(tcp.SrcPort)),
				DstPort: strconv.Itoa(int(tcp.DstPort)),
				Fingerprints: JAFingerprints{
					JA3:     MD5(ja3Str),
					JA3byte: ja3Str,
				},
			})
			*id++

		} else if tlsPayload[5] == 0x02 { // Server Hello
			ja3sHex := ja3.BarePacketJa3s(packet)

			// Найти соответствующий Client Hello по номеру порта и IP-адресу
			for i, h := range *handshakes {
				if h.Fingerprints.JA3s == "" && h.ID < *id {
					ja3sStr := string(ja3sHex)
					(*handshakes)[i].Fingerprints.JA3s = MD5(ja3sStr)
					(*handshakes)[i].Fingerprints.JA3sbyte = ja3sStr
					break
				}
			}
		}
	}

	return nil
}

// saveHandshakes сохраняет пакеты и данные в JSON файл
func saveHandshakes(handshakes []TLSHandshake, path string) error {
	fileName := getNameFromPath(path)
	jsonPath := fmt.Sprintf("%s/%s.json", "json_fingerprints", fileName)

	jsonData, err := json.MarshalIndent(handshakes, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	file, err := os.Create(jsonPath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(jsonData))

	return nil
}

// getNameFromPath возвращает имя файла из полного пути
func getNameFromPath(path string) string {
	pcapFileName := strings.Split(path, "/")
	jsonFileName := strings.Split(pcapFileName[len(pcapFileName)-1], ".")[0]
	return jsonFileName
}
