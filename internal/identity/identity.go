// Package identity resolve como o coletor se autentica no painel.
//
// Espelha o fluxo do vd-agent (backend/cmd/agent/identity.go no painel):
// credencial própria de dispositivo, obtida uma vez por enrollment, substitui o
// COLLECTOR_TOKEN compartilhado — que era o mesmo em todos os coletores de
// todas as unidades, então qualquer máquina comprometida declarava a filial que
// quisesse. Divergência de comportamento entre agente e coletor é defeito.
package identity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Credential é a identidade própria deste coletor, obtida uma vez no
// enrollment e persistida em disco.
type Credential struct {
	DeviceID string `json:"device_id"`
	Token    string `json:"device_token"`
	SiteID   uint   `json:"site_id"`
	Kind     string `json:"kind"`
}

// CredentialPath é onde a credencial vive. Fica em diretório de estado do
// sistema, não no do usuário: o coletor roda como serviço e não tem HOME
// confiável.
func CredentialPath() string {
	if v := strings.TrimSpace(os.Getenv("COLLECTOR_CREDENTIAL_PATH")); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "vd-collector", "credential.json")
	}
	// /var/lib e não /etc: a credencial é obtida em tempo de execução, então é
	// estado e não configuração. E o serviço systemd roda com
	// ProtectSystem=strict, que deixa /etc somente-leitura — gravar ali
	// falharia DEPOIS de o convite já ter sido queimado no painel, que é a
	// pior hora possível para falhar.
	return "/var/lib/vd-collector/credential.json"
}

// machineID é o identificador estável da máquina, fornecido pelo sistema.
//
// Preferido ao hostname porque hostname muda: renomear o servidor da unidade
// partiria o histórico dele em duas séries no painel.
func machineID() string {
	if v := strings.TrimSpace(os.Getenv("COLLECTOR_MACHINE_ID")); v != "" {
		return v
	}

	// /etc/machine-id é padrão em qualquer Linux com systemd; o dbus é o
	// fallback das distribuições que não o criam.
	for _, caminho := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(caminho); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}

	// Sem identificador do sistema — container sem /etc/machine-id — geramos
	// um e o guardamos junto da credencial. Vale menos que o do sistema
	// (reinstalar gera outro), mas vale mais que hostname, que muda sozinho.
	return persistedFallbackID()
}

func persistedFallbackID() string {
	caminho := filepath.Join(filepath.Dir(CredentialPath()), "machine-id")

	if b, err := os.ReadFile(caminho); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id
		}
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("AVISO: nao foi possivel gerar identificador de maquina: %v", err)
		return ""
	}
	id := hex.EncodeToString(buf)

	if err := os.MkdirAll(filepath.Dir(caminho), 0o755); err == nil {
		if err := os.WriteFile(caminho, []byte(id+"\n"), 0o600); err != nil {
			log.Printf("AVISO: identificador de maquina nao foi persistido: %v", err)
		}
	}
	return id
}

// Load lê a credencial persistida, se houver uma utilizável.
func Load() (Credential, bool) {
	b, err := os.ReadFile(CredentialPath())
	if err != nil {
		return Credential{}, false
	}

	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		log.Printf("AVISO: credencial ilegivel em %s: %v", CredentialPath(), err)
		return Credential{}, false
	}
	if c.DeviceID == "" || c.Token == "" {
		return Credential{}, false
	}
	return c, true
}

// Save persiste a credencial obtida no enrollment.
func Save(c Credential) error {
	caminho := CredentialPath()
	if err := os.MkdirAll(filepath.Dir(caminho), 0o755); err != nil {
		return err
	}

	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	// 0600: o segredo vale por si só. Um arquivo legível por todos entrega a
	// identidade do dispositivo a qualquer processo da máquina.
	return os.WriteFile(caminho, append(b, '\n'), 0o600)
}

// Enroll troca o convite de uso único pela credencial própria deste coletor.
//
// Roda uma vez, na instalação. Depois disso o convite já foi queimado no
// painel e não serve para mais nada, nem para quem o interceptar.
func Enroll(client *http.Client, serverURL, conviteToken, hostname string) (Credential, error) {
	corpo, err := json.Marshal(map[string]string{
		"enrollment_token": conviteToken,
		"machine_id":       machineID(),
		"hostname":         hostname,
		"kind":             "collector",
	})
	if err != nil {
		return Credential{}, err
	}

	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/enroll", bytes.NewReader(corpo))
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Credential{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		// O corpo do erro é lido com teto: um painel mal configurado pode
		// devolver uma página inteira, e despejá-la no log do serviço não
		// ajuda ninguém.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Credential{}, fmt.Errorf("enrollment recusado (%d): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var c Credential
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return Credential{}, err
	}
	if c.DeviceID == "" || c.Token == "" {
		return Credential{}, errors.New("painel devolveu credencial incompleta")
	}
	return c, nil
}

// Resolve decide como este coletor vai se autenticar.
//
// Ordem: credencial já persistida vence tudo; senão, um convite de enrollment
// é trocado por uma; senão, o COLLECTOR_TOKEN compartilhado, que continua
// aceito durante a transição. Sem nenhum dos três o coletor não sobe — um
// coletor que roda sem conseguir enviar é pior que um que não roda, porque a
// unidade some do painel sem ninguém perceber.
func Resolve(client *http.Client, serverURL, hostname string) (Credential, string, error) {
	if c, ok := Load(); ok {
		log.Printf("credencial propria em uso (device=%s unidade=%d)", c.DeviceID, c.SiteID)
		return c, "", nil
	}

	if convite := strings.TrimSpace(os.Getenv("COLLECTOR_ENROLL_TOKEN")); convite != "" {
		c, err := Enroll(client, serverURL, convite, hostname)
		if err != nil {
			return Credential{}, "", fmt.Errorf("enrollment falhou: %w", err)
		}
		if err := Save(c); err != nil {
			// Não é fatal: o coletor já tem a credencial em memória e vai
			// reportar. Mas o convite foi queimado, então o próximo reinício
			// não conseguirá outra — e isso precisa gritar.
			log.Printf("AVISO GRAVE: credencial obtida mas NAO gravada em %s (%v). "+
				"O convite ja foi consumido; emita outro antes de reiniciar este coletor.",
				CredentialPath(), err)
		} else {
			log.Printf("enrollment concluido (device=%s unidade=%d). "+
				"Remova COLLECTOR_ENROLL_TOKEN da configuracao.", c.DeviceID, c.SiteID)
		}
		return c, "", nil
	}

	legado := strings.TrimSpace(os.Getenv("COLLECTOR_TOKEN"))
	if legado == "" {
		return Credential{}, "", errors.New("sem identidade: defina COLLECTOR_ENROLL_TOKEN para se cadastrar, " +
			"ou COLLECTOR_TOKEN para o modo compartilhado (em descontinuacao)")
	}
	log.Printf("AVISO: usando COLLECTOR_TOKEN compartilhado, que nao amarra este coletor " +
		"a uma unidade. Migre para credencial propria com COLLECTOR_ENROLL_TOKEN.")
	return Credential{}, legado, nil
}
