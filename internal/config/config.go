// Package config lê a configuração do coletor a partir do ambiente.
package config

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultInterval = 15 * time.Minute
	MinInterval     = time.Minute
)

// Config é tudo que o coletor precisa para operar numa unidade.
type Config struct {
	// ServerURL é o painel central que recebe o inventário.
	ServerURL string
	// SiteCode identifica a unidade. Precisa existir cadastrada no painel.
	SiteCode string

	CIDRs    []string
	Ports    []int
	Interval time.Duration

	// Once faz uma varredura só e encerra, para uso em cron.
	Once bool
}

// Getenv é injetável para o teste não depender do ambiente do processo.
type Getenv func(string) string

var (
	ErrMissingServerURL = errors.New("COLLECTOR_SERVER_URL não definido")
	ErrMissingSite      = errors.New("COLLECTOR_SITE não definido (código da unidade cadastrado no painel)")
	ErrMissingCIDRs     = errors.New("COLLECTOR_CIDRS não definido (ex: 192.168.0.0/24)")
)

// Load monta a configuração e valida o que é obrigatório.
func Load(getenv Getenv) (Config, error) {
	// A identidade (credencial de dispositivo, convite de enrollment ou o
	// COLLECTOR_TOKEN legado) não entra aqui: é resolvida em internal/identity,
	// porque depende de estado em disco além do ambiente.
	cfg := Config{
		ServerURL: strings.TrimRight(strings.TrimSpace(getenv("COLLECTOR_SERVER_URL")), "/"),
		SiteCode:  strings.ToLower(strings.TrimSpace(getenv("COLLECTOR_SITE"))),
		CIDRs:     SplitList(getenv("COLLECTOR_CIDRS")),
		Interval:  DefaultInterval,
		Once:      isTrue(getenv("COLLECTOR_ONCE")),
	}

	for _, raw := range SplitList(getenv("COLLECTOR_PORTS")) {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n < 65536 {
			cfg.Ports = append(cfg.Ports, n)
		}
	}

	if raw := strings.TrimSpace(getenv("COLLECTOR_INTERVAL_MIN")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			cfg.Interval = time.Duration(n) * time.Minute
		}
	}
	// Intervalo curto demais faz a varredura anterior ainda estar rodando
	// quando a próxima dispara.
	if cfg.Interval < MinInterval {
		cfg.Interval = MinInterval
	}

	switch {
	case cfg.ServerURL == "":
		return cfg, ErrMissingServerURL
	case cfg.SiteCode == "":
		return cfg, ErrMissingSite
	case len(cfg.CIDRs) == 0:
		return cfg, ErrMissingCIDRs
	}
	return cfg, nil
}

// SplitList quebra uma lista separada por vírgula, ignorando espaços e vazios.
func SplitList(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func isTrue(raw string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	return err == nil && v
}
