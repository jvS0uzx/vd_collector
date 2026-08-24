// Package scan inventaria os hosts ativos de uma rede local.
//
// A varredura é um TCP connect scan: para cada IP da faixa tenta abrir conexão
// numa lista curta de portas comuns. Quem aceita está ligado. Não usa ICMP nem
// ARP cru porque os dois exigem socket raw, ou seja, root — e o coletor deve
// rodar como serviço sem privilégio.
package scan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Portas sondadas por host. Lista curta de propósito: cobre estação Windows
// (445/3389), Linux (22), impressora (9100/515/631), NAS (5000) e web.
var DefaultPorts = []int{22, 80, 135, 139, 443, 445, 515, 631, 3389, 5000, 8080, 9100}

const (
	DefaultTimeout     = 400 * time.Millisecond
	DefaultConcurrency = 256

	// Uma faixa maior que /16 são 65 mil hosts: varredura longa demais para uma
	// rede de escritório e provavelmente erro de digitação.
	minPrefixLen = 16

	// Prazo do DNS reverso. Numa rede sem PTR cada consulta esperaria o timeout
	// inteiro do resolver.
	reverseDNSTimeout = time.Second
)

// Host é um endereço que respondeu à varredura.
type Host struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	MAC       string `json:"mac"`
	OpenPorts []int  `json:"open_ports"`
}

// Config parametriza uma varredura.
type Config struct {
	CIDRs       []string
	Ports       []int
	Timeout     time.Duration
	Concurrency int
}

// WithDefaults preenche o que não foi informado.
func (c Config) WithDefaults() Config {
	if len(c.Ports) == 0 {
		c.Ports = DefaultPorts
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.Concurrency <= 0 {
		c.Concurrency = DefaultConcurrency
	}
	return c
}

// ExpandCIDR devolve os endereços utilizáveis da faixa.
//
// Só aceita faixa privada (RFC1918 / link-local / loopback): o coletor existe
// para inventariar a rede da própria unidade, e recusar endereço público
// impede que ele seja apontado para redes de terceiros.
func ExpandCIDR(cidr string) ([]string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("faixa inválida %q: %w", cidr, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("faixa %q: só IPv4 é suportado", cidr)
	}
	if !isPrivate(network.IP) {
		return nil, fmt.Errorf("faixa %q não é privada; a varredura só cobre a rede interna", cidr)
	}

	ones, bits := network.Mask.Size()
	if ones < minPrefixLen {
		return nil, fmt.Errorf("faixa %q é grande demais (máximo /%d)", cidr, minPrefixLen)
	}

	var ips []string
	for addr := network.IP.Mask(network.Mask); network.Contains(addr); addr = nextIP(addr) {
		ips = append(ips, addr.String())
	}

	// Em /31 e /32 todo endereço é utilizável; nas demais o primeiro é a rede e
	// o último é broadcast.
	if ones < bits-1 && len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func isPrivate(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback()
}

// nextIP devolve uma cópia do endereço seguinte, sem alterar o original.
func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

// Run varre todas as faixas e devolve os hosts que responderam, ordenados por
// endereço. Uma faixa inválida não aborta a varredura das outras.
func Run(ctx context.Context, cfg Config) ([]Host, []error) {
	cfg = cfg.WithDefaults()

	var targets []string
	var errs []error
	for _, cidr := range cfg.CIDRs {
		ips, err := ExpandCIDR(cidr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		targets = append(targets, ips...)
	}
	if len(targets) == 0 {
		return nil, errs
	}

	var (
		mu    sync.Mutex
		found []Host
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, cfg.Concurrency)

	for _, ip := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ports := probe(ctx, ip, cfg.Ports, cfg.Timeout)
			if len(ports) == 0 {
				return
			}

			host := Host{IP: ip, OpenPorts: ports, Hostname: reverseDNS(ctx, ip)}

			mu.Lock()
			found = append(found, host)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	// A tabela ARP é lida depois: foram as conexões TCP desta varredura que a
	// preencheram. Lendo antes, o MAC de um host novo só apareceria no ciclo
	// seguinte.
	arp := ARPTable()
	for i := range found {
		found[i].MAC = arp[found[i].IP]
	}

	sort.Slice(found, func(i, j int) bool { return LessIP(found[i].IP, found[j].IP) })
	return found, errs
}

// probe testa as portas do host e devolve as que aceitaram conexão.
func probe(ctx context.Context, ip string, ports []int, timeout time.Duration) []int {
	var open []int
	dialer := net.Dialer{Timeout: timeout}

	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		conn.Close()
		open = append(open, port)
	}
	return open
}

func reverseDNS(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, reverseDNSTimeout)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	name := names[0]
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

// LessIP compara dois IPv4 octeto a octeto. Comparar como texto colocaria
// 172.16.1.100 antes de 172.16.1.9.
func LessIP(a, b string) bool {
	ipA, ipB := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ipA == nil || ipB == nil {
		return a < b
	}
	for i := range ipA {
		if ipA[i] != ipB[i] {
			return ipA[i] < ipB[i]
		}
	}
	return false
}
