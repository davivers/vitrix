# Vitrix visual identity

| Role | Colour |
|---|---|
| Dark background (glass) | `#0B1020` |
| Light surface | `#F5F6F8` |
| Primary accent | `#6D5BF0` |
| Glow | `#22D3EE` |
| SIEM outputs (logo) | `#2A78D6` `#EB6834` `#1BAF7A` |

## UI (dark "Ultraviolet Ink" theme)

Tokens live in `web/src/index.css`. Cards are solid ink layers (`.glass`, no blur) over a violet-black background with one violet glow and a faint detection grid. `heat-0..4` (`#191527 #2B2160 #43328F #6247C9 #8A74F5`) are the coverage ramp.

| Token | Value | Use |
|---|---|---|
| `bg` | `#0F0B1C` | page background |
| `surface` / `surface-2` / `surface-3` | lavender (`#D9CEFF`) at 5% / 8% / 12% | cards, chips, hover |
| `line` | lavender at 12% | borders and dividers |
| `strong` / `text` / `muted` / `subtle` | `#FFFFFF` `#ECE8F7` `#B0A9C8` `#9189AA` | titles, body, secondary, labels |
| `brand` | `#6B54F2` | primary button background |
| `accent` | `#A292FF` | active tab, focus, links, chart series (contrast on dark) |
| `glow` | `#22D3EE` | editor cursor, background glow |
| `good` / `warn` / `bad` | `#3DDC97` `#F5B83D` `#FF7A85` | status only, always with icon and text |
| `siem-splunk` / `siem-microsoft` / `siem-elastic` | `#5AA9FF` `#F59A6B` `#34D3A3` | marker next to the SPL/KQL/EQL label |

The UI SIEM colours are lighter versions of the logo's, for contrast on the dark background. SIEM colours are markers beside a label, never chart series: charts use a single violet series with the number written.

Violet and cyan are brand only. Green, yellow and red are reserved for status.
Fonts: Inter (UI) and JetBrains Mono (code).
The logo text uses a system font; convert the text to outlines before publishing.
Tagline: "Write once. Detect on any SIEM."
