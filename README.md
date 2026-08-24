# vd_collector

Coletor de inventário de rede para o painel [vd_stats / DockKeeper](https://github.com/jvS0uzx/vd_stats).

Varre a rede local de uma unidade e envia o resultado — quais máquinas estão
ligadas, com que nome, MAC e portas abertas — para um painel central.

## Por que existe

O painel só enxerga a rede onde o processo dele roda. Com o painel numa VPS ou
na matriz, nenhuma varredura alcança a LAN das filiais: pacote de descoberta não
atravessa a internet.

O coletor faz o papel do *proxy* do Zabbix. Roda dentro da unidade, varre
localmente e faz push do inventário para fora. Uma instância por unidade,
apontando todas para o mesmo painel.

```
Unidade A ── coletor ──┐
Unidade B ── coletor ──┼──► painel central ──► operador
Unidade C ── coletor ──┘
```

É um projeto separado de propósito: o que se instala nos servidores das
unidades não precisa carregar o painel, o banco nem as credenciais SSH.

## Como varre

TCP connect scan. Para cada endereço da faixa, tenta abrir conexão numa lista
curta de portas comuns; quem aceita está ligado.

Não usa ICMP nem ARP cru porque os dois exigem socket raw — ou seja, root. O
coletor roda como serviço sem privilégio.

O MAC vem do cache ARP do kernel, lido **depois** da varredura: foram as
conexões TCP dela que preencheram a tabela. Isso sai de graça, sem gerar um
único pacote a mais.

### Contenção

`ExpandCIDR` recusa:

- faixa que não seja privada (RFC1918, link-local, loopback)
- faixa maior que `/16`
- endereço IPv6

O propósito é inventariar a rede da própria unidade. Recusar endereço público
impede que o coletor seja apontado para rede de terceiros.

Uma faixa inválida no meio da lista é registrada e ignorada; as outras seguem.

## Instalação

```bash
go build -o collector ./cmd/collector

sudo cp collector /usr/local/bin/vd-collector
sudo cp deploy/vd-collector.service /etc/systemd/system/
sudo cp deploy/collector.env /etc/vd-collector.env
sudo chmod 600 /etc/vd-collector.env
sudoedit /etc/vd-collector.env

sudo systemctl enable --now vd-collector
journalctl -u vd-collector -f
```

Para rodar por cron em vez de serviço, use `COLLECTOR_ONCE=true`.

## Configuração

Tudo por ambiente. Sem as quatro primeiras o coletor recusa subir.

| Variável | Obrigatória | Descrição |
|---|---|---|
| `COLLECTOR_SERVER_URL` | sim | URL do painel central |
| `COLLECTOR_SITE` | sim | código da unidade, cadastrado na tela Unidades |
| `COLLECTOR_CIDRS` | sim | faixas varridas, separadas por vírgula |
| `COLLECTOR_ENROLL_TOKEN` | identidade | convite de uso único emitido no painel; trocado por credencial própria no primeiro boot |
| `COLLECTOR_TOKEN` | identidade | modo compartilhado em descontinuação: mesmo valor de `AGENT_INGEST_TOKEN` no painel |
| `COLLECTOR_CREDENTIAL_PATH` | não | onde a credencial fica (padrão `/var/lib/vd-collector/credential.json`) |
| `COLLECTOR_MACHINE_ID` | não | identificador estável da máquina; vazio usa `/etc/machine-id` |
| `COLLECTOR_INTERVAL_MIN` | não | minutos entre varreduras (mínimo 1, padrão 15) |
| `COLLECTOR_PORTS` | não | portas sondadas; vazio usa a lista padrão |
| `COLLECTOR_ONCE` | não | `true` varre uma vez e encerra |

Identidade: o coletor precisa de **uma** das três — credencial já persistida,
`COLLECTOR_ENROLL_TOKEN` ou `COLLECTOR_TOKEN`. Sem nenhuma ele recusa subir,
porque um coletor que roda sem conseguir enviar faz a unidade sumir do painel
sem ninguém perceber.

A unidade precisa existir no painel antes. Criar automaticamente permitiria que
um token vazado poluísse o cadastro com unidades inventadas.

## Identidade e primeiro boot (enrollment)

Cada coletor tem credencial própria, amarrada à unidade — o mesmo fluxo do
`vd-agent` do painel:

1. Um admin global emite um convite no painel (`POST /api/enroll/tokens`, com
   `kind: "collector"` e a unidade). O convite é de uso único e vale 24 horas.
2. O convite vai em `COLLECTOR_ENROLL_TOKEN` no primeiro boot. O coletor o
   troca por `device_id` + segredo (`POST /api/enroll`) e grava a credencial em
   `/var/lib/vd-collector/credential.json`, modo 0600 — o serviço systemd cria
   o diretório via `StateDirectory=vd-collector`.
3. Nos boots seguintes a credencial persistida vence tudo; a variável do
   convite pode ser removida, porque o convite já foi queimado no painel.
4. Todo envio passa a carregar `X-Device-Id`/`X-Device-Token`. A unidade sai da
   credencial no lado do painel — o `site_code` do corpo vira conferência, não
   fonte. Revogar o dispositivo no painel derruba só este coletor.

Perdeu o arquivo da credencial? Emita outro convite e refaça o primeiro boot:
não existe releitura, o painel guarda só o hash do segredo.

O `COLLECTOR_TOKEN` compartilhado continua aceito durante a transição, com
aviso no log a cada uso.

## O que o painel faz com o envio

Upsert por IP. Preserva `first_seen`, e o cadastro que o operador preencheu no
painel — sala, responsável, patrimônio — nunca é sobrescrito por um coletor.
`hostname` e `mac` só substituem o valor guardado quando vieram preenchidos: um
DNS reverso que falhou não pode apagar o nome já conhecido.

## Segurança

- Roda sem privilégio (`DynamicUser`, `NoNewPrivileges`, `ProtectSystem=strict`).
- Nenhum segredo vai para o log: mensagens de erro passam por redação (token
  compartilhado e segredo da credencial), porque o `*url.Error` do Go embute a
  URL inteira.
- Credencial recusada (401/503) não é repetida — é configuração, não
  instabilidade. Falha de rede tenta 3 vezes com intervalo de 5s.
- A credencial de dispositivo é própria deste coletor: revogá-la no painel não
  afeta nenhum outro.
- Inventário vazio **com** falha em todas as faixas não é enviado, para não
  apagar o último estado bom no painel.

## Testes

```bash
go test ./...
```
