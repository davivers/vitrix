# Identidade visual do Vitrix

| Papel | Cor |
|---|---|
| Fundo escuro (vidro) | `#0B1020` |
| Superfície clara | `#F5F6F8` |
| Acento principal | `#6D5BF0` |
| Brilho | `#22D3EE` |
| Saídas dos SIEMs (logo) | `#2A78D6` `#EB6834` `#1BAF7A` |

## Interface (tema escuro "vidro")

Tokens em `web/src/index.css`. Cartões são superfícies translúcidas (`.glass`) sobre o fundo com brilho violeta e ciano.

| Token | Valor | Uso |
|---|---|---|
| `bg` | `#070B16` | fundo da página |
| `surface` / `surface-2` / `surface-3` | branco a 4% / 7% / 10% | cartões, chips, hover |
| `line` | branco a 9% | bordas e divisórias |
| `strong` / `text` / `muted` / `subtle` | `#FFFFFF` `#E8ECF5` `#A3ADC4` `#8791AB` | títulos, corpo, secundário, rótulos |
| `brand` | `#6D5BF0` | fundo do botão principal |
| `accent` | `#8B7CF6` | aba ativa, foco, links (contraste no escuro) |
| `glow` | `#22D3EE` | cursor do editor, brilho de fundo |
| `good` / `warn` / `bad` | `#34D399` `#FBBF24` `#F87171` | só status, sempre com ícone e texto |
| `siem-splunk` / `siem-microsoft` / `siem-elastic` | `#5AA9FF` `#F59A6B` `#34D3A3` | quadradinho ao lado do rótulo SPL/KQL/EQL |

As cores de SIEM da interface são versões mais claras das do logo, para contraste sobre o fundo escuro.

Violeta e ciano só na marca. Verde, amarelo e vermelho ficam reservados para status.
Fontes: Inter (interface) e JetBrains Mono (código).
O texto dos logos usa fonte do sistema; antes de publicar, converta o texto em curvas.
Tagline: "Escreva uma vez. Detecte em qualquer SIEM."
