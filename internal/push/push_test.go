package push

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// clienteDeTeste encurta o intervalo entre tentativas para o teste não
// esperar os segundos reais da produção.
func clienteDeTeste(url string, id Identity) *Client {
	c := New(url, id)
	c.delay = time.Millisecond
	return c
}

func TestEnviaHeadersDaCredencialPropria(t *testing.T) {
	var got http.Header
	var body Payload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := clienteDeTeste(srv.URL, Identity{DeviceID: "dev-1", DeviceToken: "segredo-1"})
	err := c.Send(context.Background(), Payload{SiteCode: "norte", CollectorVersion: "1.0.0"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got.Get("X-Device-Id") != "dev-1" || got.Get("X-Device-Token") != "segredo-1" {
		t.Errorf("headers de dispositivo = %q/%q", got.Get("X-Device-Id"), got.Get("X-Device-Token"))
	}
	if got.Get("X-Agent-Token") != "" {
		t.Errorf("X-Agent-Token não deveria ir junto da credencial própria")
	}
	if body.SiteCode != "norte" {
		t.Errorf("site_code = %q", body.SiteCode)
	}
}

func TestEnviaTokenLegadoSemCredencial(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := clienteDeTeste(srv.URL, Identity{LegacyToken: "token-legado"})
	if err := c.Send(context.Background(), Payload{}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got.Get("X-Agent-Token") != "token-legado" {
		t.Errorf("X-Agent-Token = %q", got.Get("X-Agent-Token"))
	}
	if got.Get("X-Device-Id") != "" || got.Get("X-Device-Token") != "" {
		t.Errorf("headers de dispositivo deveriam estar vazios no modo legado")
	}
}

// Credencial recusada é configuração errada, não instabilidade: repetir só
// martelaria o painel com a mesma credencial inválida.
func TestCredencialRecusadaNaoRepete(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusServiceUnavailable} {
		var chamadas atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			chamadas.Add(1)
			w.WriteHeader(status)
		}))

		c := clienteDeTeste(srv.URL, Identity{LegacyToken: "x"})
		err := c.Send(context.Background(), Payload{})
		srv.Close()

		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("HTTP %d: erro = %v, esperado ErrUnauthorized", status, err)
		}
		if n := chamadas.Load(); n != 1 {
			t.Errorf("HTTP %d: %d tentativas, esperado 1", status, n)
		}
	}
}

func TestRepeteEmFalhaTransitoriaEEntrega(t *testing.T) {
	var chamadas atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if chamadas.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := clienteDeTeste(srv.URL, Identity{LegacyToken: "x"})
	if err := c.Send(context.Background(), Payload{}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if n := chamadas.Load(); n != 3 {
		t.Errorf("%d tentativas, esperado 3", n)
	}
}

func TestDesisteAposEsgotarTentativas(t *testing.T) {
	var chamadas atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chamadas.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := clienteDeTeste(srv.URL, Identity{LegacyToken: "x"})
	err := c.Send(context.Background(), Payload{})
	if err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("erro = %v, esperada falha transitória esgotada", err)
	}
	if !strings.Contains(err.Error(), "3 tentativas") {
		t.Errorf("mensagem sem o total de tentativas: %v", err)
	}
	if n := chamadas.Load(); n != int32(maxAttempts) {
		t.Errorf("%d tentativas, esperado %d", n, maxAttempts)
	}
}

// Falha de rede não é ErrUnauthorized: o ciclo seguinte deve tentar de novo.
func TestFalhaDeRedeNaoEhCredencialRecusada(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := clienteDeTeste(url, Identity{LegacyToken: "x"})
	err := c.Send(context.Background(), Payload{})
	if err == nil {
		t.Fatal("esperava erro com o painel fora do ar")
	}
	if errors.Is(err, ErrUnauthorized) {
		t.Errorf("falha de rede classificada como credencial recusada: %v", err)
	}
}

// O *url.Error embute a URL inteira na mensagem. Se um segredo aparecer por
// lá, ele não pode chegar ao log.
func TestSegredosNaoVazamNaMensagemDeErro(t *testing.T) {
	casos := []struct {
		nome    string
		id      Identity
		segredo string
		marca   string
	}{
		{"token legado", Identity{LegacyToken: "tok3n-sup3r-s3cr3to"}, "tok3n-sup3r-s3cr3to", "<COLLECTOR_TOKEN>"},
		{"credencial propria", Identity{DeviceID: "dev", DeviceToken: "s3gr3do-d3-d3vic3"}, "s3gr3do-d3-d3vic3", "<CREDENCIAL>"},
	}
	for _, caso := range casos {
		t.Run(caso.nome, func(t *testing.T) {
			// O segredo dentro da URL força o *url.Error a citá-lo.
			c := clienteDeTeste("http://"+caso.segredo+".invalid:0", caso.id)
			err := c.Send(context.Background(), Payload{})
			if err == nil {
				t.Fatal("esperava erro de rede")
			}
			if strings.Contains(err.Error(), caso.segredo) {
				t.Fatalf("segredo vazou na mensagem: %v", err)
			}
			if !strings.Contains(err.Error(), caso.marca) {
				t.Errorf("mensagem sem a marca de redação %q: %v", caso.marca, err)
			}
		})
	}
}
