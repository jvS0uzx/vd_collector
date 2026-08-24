// Package push envia o inventário coletado ao painel central.
package push

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/joaov/vd_collector/internal/scan"
)

const (
	// Prazo do envio. Inventário de uma /24 cabe em poucos KB, então um envio
	// que passa disso indica painel indisponível, não payload grande.
	timeout = 30 * time.Second

	// Tentativas antes de descartar o ciclo. O próximo já traz o inventário
	// atualizado, então insistir muito não agrega.
	maxAttempts = 3
	retryDelay  = 5 * time.Second

	endpointPath = "/api/ingest/inventory"
)

// ErrUnauthorized indica credencial recusada ou ingestão desligada no painel.
// Não adianta repetir: é configuração, não instabilidade.
var ErrUnauthorized = errors.New("credencial recusada pelo painel")

// Payload é o corpo enviado ao painel.
type Payload struct {
	SiteCode         string      `json:"site_code"`
	CollectorVersion string      `json:"collector_version"`
	Hosts            []scan.Host `json:"hosts"`
}

// Identity é o que o cliente apresenta ao painel: a credencial própria de
// dispositivo quando existe, ou o token compartilhado da transição. O mesmo
// par de headers do vd-agent — X-Device-Id/X-Device-Token, com X-Agent-Token
// como legado.
type Identity struct {
	DeviceID    string
	DeviceToken string
	LegacyToken string
}

// Client fala com o painel central.
type Client struct {
	baseURL string
	id      Identity
	http    *http.Client

	// delay é campo, não constante, para o teste não esperar segundos reais.
	delay time.Duration
}

func New(baseURL string, id Identity) *Client {
	return &Client{
		baseURL: baseURL,
		id:      id,
		http:    &http.Client{Timeout: timeout},
		delay:   retryDelay,
	}
}

// Send entrega o inventário, repetindo em falha transitória.
func (c *Client) Send(ctx context.Context, payload Payload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("erro ao serializar o inventário: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := c.post(ctx, body)
		if err == nil {
			return nil
		}
		// Credencial errada não melhora com repetição.
		if errors.Is(err, ErrUnauthorized) {
			return err
		}
		lastErr = err

		if attempt == maxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.delay):
		}
	}
	return fmt.Errorf("envio falhou após %d tentativas: %w", maxAttempts, lastErr)
}

func (c *Client) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+endpointPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.id.DeviceID != "" {
		req.Header.Set("X-Device-Id", c.id.DeviceID)
		req.Header.Set("X-Device-Token", c.id.DeviceToken)
	} else {
		req.Header.Set("X-Agent-Token", c.id.LegacyToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return c.redact(err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusAccepted:
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusServiceUnavailable:
		return fmt.Errorf("%w (HTTP %d)", ErrUnauthorized, resp.StatusCode)
	default:
		return fmt.Errorf("painel respondeu HTTP %d", resp.StatusCode)
	}
}

// redact tira os segredos de mensagens de erro. O *url.Error do Go embute a
// URL inteira; se algum dia um segredo andar por lá, ele não pode ir para o
// log.
func (c *Client) redact(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if c.id.DeviceToken != "" {
		msg = strings.ReplaceAll(msg, c.id.DeviceToken, "<CREDENCIAL>")
	}
	if c.id.LegacyToken != "" {
		msg = strings.ReplaceAll(msg, c.id.LegacyToken, "<COLLECTOR_TOKEN>")
	}
	return errors.New(msg)
}
