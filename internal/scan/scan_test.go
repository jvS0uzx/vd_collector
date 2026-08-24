package scan

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestExpandCIDRDescartaRedeEBroadcast(t *testing.T) {
	ips, err := ExpandCIDR("192.168.10.0/29")
	if err != nil {
		t.Fatalf("ExpandCIDR: %v", err)
	}
	if len(ips) != 6 || ips[0] != "192.168.10.1" || ips[5] != "192.168.10.6" {
		t.Fatalf("faixa = %v", ips)
	}
}

func TestExpandCIDRAtravessaOctetos(t *testing.T) {
	ips, err := ExpandCIDR("10.0.0.0/23")
	if err != nil {
		t.Fatalf("ExpandCIDR: %v", err)
	}
	if len(ips) != 510 {
		t.Fatalf("len = %d, esperado 510", len(ips))
	}
	if ips[254] != "10.0.0.255" || ips[255] != "10.0.1.0" {
		t.Fatalf("virada de octeto: %s -> %s", ips[254], ips[255])
	}
}

// O coletor inventaria a rede da própria unidade. Aceitar faixa pública o
// transformaria em scanner apontável para terceiros.
func TestExpandCIDRRecusaFaixaPublica(t *testing.T) {
	for _, cidr := range []string{"8.8.8.0/24", "82.38.173.0/24"} {
		_, err := ExpandCIDR(cidr)
		if err == nil {
			t.Errorf("%s foi aceita", cidr)
		} else if !strings.Contains(err.Error(), "privada") {
			t.Errorf("%s: erro inesperado %v", cidr, err)
		}
	}
}

func TestExpandCIDRRecusaFaixaGigante(t *testing.T) {
	if _, err := ExpandCIDR("10.0.0.0/8"); err == nil {
		t.Fatal("/8 foi aceita")
	}
}

func TestRunIgnoraFaixaInvalidaEContinua(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	hosts, errs := Run(context.Background(), Config{
		CIDRs:   []string{"8.8.8.0/24", "127.0.0.1/32"},
		Ports:   []int{port},
		Timeout: 300 * time.Millisecond,
	})

	if len(errs) != 1 {
		t.Fatalf("erros = %v, esperado 1", errs)
	}
	if len(hosts) != 1 || hosts[0].IP != "127.0.0.1" {
		t.Fatalf("hosts = %+v", hosts)
	}
}

func TestRunRespeitaCancelamento(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	Run(ctx, Config{CIDRs: []string{"10.10.0.0/24"}, Timeout: time.Second})
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancelamento demorou %s", elapsed)
	}
}

func TestLessIP(t *testing.T) {
	if !LessIP("192.168.1.9", "192.168.1.10") {
		t.Error("comparação caiu para texto")
	}
}
