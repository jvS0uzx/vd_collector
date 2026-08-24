package scan

import (
	"bufio"
	"os"
	"strings"
)

// ARPTable lê o cache ARP do kernel e mapeia IP para MAC.
//
// É de graça: o kernel já preencheu essa tabela durante a varredura, então o
// endereço físico sai sem gerar um único pacote a mais. Serve para o inventário
// identificar o equipamento mesmo quando o IP muda por DHCP.
//
// Só existe no Linux; em outro sistema devolve mapa vazio e o inventário segue
// sem MAC.
func ARPTable() map[string]string {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return map[string]string{}
	}
	defer file.Close()

	macByIP := make(map[string]string)
	scanner := bufio.NewScanner(file)
	scanner.Scan() // cabeçalho

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip, mac := fields[0], strings.ToLower(fields[3])
		// 00:00:00:00:00:00 é entrada incompleta (host não respondeu ao ARP).
		if mac == "00:00:00:00:00:00" {
			continue
		}
		macByIP[ip] = mac
	}
	return macByIP
}
