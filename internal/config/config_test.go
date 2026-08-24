package config

import (
	"errors"
	"testing"
	"time"
)

func env(pairs map[string]string) Getenv {
	return func(k string) string { return pairs[k] }
}

func validEnv() map[string]string {
	return map[string]string{
		"COLLECTOR_SERVER_URL": "https://painel.exemplo/",
		"COLLECTOR_SITE":       "  NORTE ",
		"COLLECTOR_CIDRS":      "192.168.0.0/24, 10.0.1.0/24",
	}
}

func TestLoadValida(t *testing.T) {
	cfg, err := Load(env(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ServerURL != "https://painel.exemplo" {
		t.Errorf("ServerURL = %q, a barra final deveria sair", cfg.ServerURL)
	}
	if cfg.SiteCode != "norte" {
		t.Errorf("SiteCode = %q, esperado normalizado", cfg.SiteCode)
	}
	if len(cfg.CIDRs) != 2 {
		t.Errorf("CIDRs = %v", cfg.CIDRs)
	}
	if cfg.Interval != DefaultInterval {
		t.Errorf("Interval = %v, esperado o padrão", cfg.Interval)
	}
}

func TestLoadExigeObrigatorios(t *testing.T) {
	cases := map[string]error{
		"COLLECTOR_SERVER_URL": ErrMissingServerURL,
		"COLLECTOR_SITE":       ErrMissingSite,
		"COLLECTOR_CIDRS":      ErrMissingCIDRs,
	}
	for missing, want := range cases {
		vars := validEnv()
		delete(vars, missing)

		if _, err := Load(env(vars)); !errors.Is(err, want) {
			t.Errorf("sem %s: erro = %v, esperado %v", missing, err, want)
		}
	}
}

// Intervalo curto demais faria a varredura seguinte disparar com a anterior
// ainda em curso.
func TestLoadAplicaIntervaloMinimo(t *testing.T) {
	vars := validEnv()
	vars["COLLECTOR_INTERVAL_MIN"] = "0"
	cfg, _ := Load(env(vars))
	if cfg.Interval != DefaultInterval {
		t.Errorf("intervalo 0 = %v, esperado o padrão", cfg.Interval)
	}

	vars["COLLECTOR_INTERVAL_MIN"] = "1"
	cfg, _ = Load(env(vars))
	if cfg.Interval != time.Minute {
		t.Errorf("intervalo = %v, esperado 1min", cfg.Interval)
	}
}

func TestLoadPortasInvalidasSaoIgnoradas(t *testing.T) {
	vars := validEnv()
	vars["COLLECTOR_PORTS"] = "22, abc, 70000, 0, 3389"
	cfg, _ := Load(env(vars))

	if len(cfg.Ports) != 2 || cfg.Ports[0] != 22 || cfg.Ports[1] != 3389 {
		t.Errorf("Ports = %v, esperado [22 3389]", cfg.Ports)
	}
}

func TestSplitList(t *testing.T) {
	got := SplitList(" a , ,b,  ")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("SplitList = %v", got)
	}
	if len(SplitList("")) != 0 {
		t.Error("lista vazia deveria devolver nada")
	}
}
