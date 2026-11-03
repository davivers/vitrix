# Vitrix visual identity

| Role | Colour |
|---|---|
| Dark background (glass) | `#0B1020` |
| Light surface | `#F5F6F8` |
| Primary accent | `#6D5BF0` |
| Glow | `#22D3EE` |
| SIEM outputs (logo) | `#2A78D6` `#EB6834` `#1BAF7A` |

## UI (dark "glass" theme)

Tokens live in `web/src/index.css`. Cards are translucent surfaces (`.glass`) over a background with a violet and cyan glow.

| Token | Value | Use |
|---|---|---|
| `bg` | `#070B16` | page background |
| `surface` / `surface-2` / `surface-3` | white at 4% / 7% / 10% | cards, chips, hover |
| `line` | white at 9% | borders and dividers |
| `strong` / `text` / `muted` / `subtle` | `#FFFFFF` `#E8ECF5` `#A3ADC4` `#8791AB` | titles, body, secondary, labels |
| `brand` | `#6D5BF0` | primary button background |
| `accent` | `#8B7CF6` | active tab, focus, links, chart series (contrast on dark) |
| `glow` | `#22D3EE` | editor cursor, background glow |
| `good` / `warn` / `bad` | `#34D399` `#FBBF24` `#F87171` | status only, always with icon and text |
| `siem-splunk` / `siem-microsoft` / `siem-elastic` | `#5AA9FF` `#F59A6B` `#34D3A3` | marker next to the SPL/KQL/EQL label |

The UI SIEM colours are lighter versions of the logo's, for contrast on the dark background. SIEM colours are markers beside a label, never chart series: charts use a single violet series with the number written.

Violet and cyan are brand only. Green, yellow and red are reserved for status.
Fonts: Inter (UI) and JetBrains Mono (code).
The logo text uses a system font; convert the text to outlines before publishing.
Tagline: "Write once. Detect on any SIEM."
