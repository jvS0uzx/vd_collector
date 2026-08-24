// Command collector varre a rede local de uma unidade e envia o inventário
// para o painel vd_stats.
//
// Existe porque o painel só enxerga a rede onde roda: com o painel central
// numa VPS ou na matriz, nenhuma varredura alcança a LAN das filiais. O
// coletor faz o papel do proxy do Zabbix — roda dentro da unidade, varre
// localmente e faz push do resultado.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joaov/vd_collector/internal/config"
	"github.com/joaov/vd_collector/internal/identity"
	"github.com/joaov/vd_collector/internal/push"
	"github.com/joaov/vd_collector/internal/scan"
)

// Version identifica a build no inventário do painel.
const Version = "1.0.0"

func main() {
	log.SetPrefix("[collector] ")
	log.SetFlags(log.LstdFlags)

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatalf("configuração inválida: %v", err)
	}

	log.Printf("v%s unidade=%q faixas=%v destino=%s intervalo=%s",
		Version, cfg.SiteCode, cfg.CIDRs, cfg.ServerURL, cfg.Interval)

	hostname, _ := os.Hostname()
	cred, legado, err := identity.Resolve(&http.Client{Timeout: 30 * time.Second}, cfg.ServerURL, hostname)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// SIGTERM do systemd encerra a varredura em curso em vez de matar o
	// processo no meio do envio.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := push.New(cfg.ServerURL, push.Identity{
		DeviceID:    cred.DeviceID,
		DeviceToken: cred.Token,
		LegacyToken: legado,
	})

	if cfg.Once {
		if err := cycle(ctx, cfg, client); err != nil {
			log.Fatalf("ciclo falhou: %v", err)
		}
		return
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		if err := cycle(ctx, cfg, client); err != nil {
			log.Printf("ciclo falhou: %v", err)
		}
		select {
		case <-ctx.Done():
			log.Println("encerrado")
			return
		case <-ticker.C:
		}
	}
}

// cycle faz uma varredura e envia o resultado.
func cycle(ctx context.Context, cfg config.Config, client *push.Client) error {
	started := time.Now()

	hosts, errs := scan.Run(ctx, scan.Config{CIDRs: cfg.CIDRs, Ports: cfg.Ports})
	for _, err := range errs {
		log.Printf("faixa ignorada: %v", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	log.Printf("varredura: %d hosts em %s", len(hosts), time.Since(started).Round(time.Millisecond))

	// Inventário vazio ainda é informação — significa rede fora do ar — mas
	// enviar isso apagaria o último estado bom se todas as faixas falharam.
	if len(hosts) == 0 && len(errs) > 0 {
		return nil
	}

	return client.Send(ctx, push.Payload{
		SiteCode:         cfg.SiteCode,
		CollectorVersion: Version,
		Hosts:            hosts,
	})
}
