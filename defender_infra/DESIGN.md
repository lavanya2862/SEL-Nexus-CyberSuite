---
name: SEL Nexus CyberSuite
description: A calm slate-navy operations room on a faint dot field, where one blue carries every action.
colors:
  canvas: "#141e31"
  panel: "#1f2a3f"
  raised: "#26324a"
  well: "#2a3751"
  field: "#172134"
  hairline: "#33415d"
  hairline-strong: "#44547a"
  ink: "#f1f5f9"
  ink-2: "#cbd5e1"
  ink-3: "#94a3b8"
  blue: "#3b82f6"
  blue-hi: "#5294f8"
  sky: "#60a0ff"
  signal: "#f07a40"
  teal: "#22b07d"
  violet: "#a397f5"
  amber: "#e0a020"
  rose: "#ec6a96"
typography:
  display:
    fontFamily: "Inter Variable, Segoe UI, system-ui, sans-serif"
    fontSize: "clamp(44px, 4vw, 54px)"
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "-0.03em"
  headline:
    fontFamily: "Inter Variable, Segoe UI, system-ui, sans-serif"
    fontSize: "24px"
    fontWeight: 600
    lineHeight: 1.33
    letterSpacing: "-0.025em"
  title:
    fontFamily: "Inter Variable, Segoe UI, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "-0.01em"
  body:
    fontFamily: "Inter Variable, Segoe UI, system-ui, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.43
    fontFeature: "'cv11', 'ss01'"
  metric:
    fontFamily: "Inter Variable, Segoe UI, system-ui, sans-serif"
    fontSize: "34px"
    fontWeight: 400
    lineHeight: 1
    letterSpacing: "-0.025em"
    fontFeature: "'tnum'"
  label:
    fontFamily: "Inter Variable, Segoe UI, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 500
    lineHeight: 1.33
rounded:
  chip: "6px"
  control-sm: "8px"
  control: "10px"
  inset: "12px"
  float: "16px"
  panel: "20px"
  stage: "24px"
  pill: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  card-tight: "20px"
  card: "24px"
  section: "48px"
components:
  button-primary:
    backgroundColor: "{colors.blue}"
    textColor: "#ffffff"
    rounded: "{rounded.control}"
    height: "56px"
    typography: "{typography.title}"
  button-primary-hover:
    backgroundColor: "{colors.blue-hi}"
  button-secondary:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control-sm}"
    height: "36px"
    padding: "0 12px"
  button-secondary-hover:
    backgroundColor: "{colors.well}"
  input-field:
    backgroundColor: "{colors.field}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    height: "56px"
    padding: "0 16px"
  panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
    padding: "24px"
  chip:
    backgroundColor: "{colors.well}"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.chip}"
    padding: "4px 8px"
    typography: "{typography.label}"
  filter-pill:
    backgroundColor: "transparent"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.pill}"
    padding: "4px 12px"
  nav-item:
    backgroundColor: "transparent"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.control}"
    height: "40px"
  nav-item-active:
    textColor: "{colors.ink}"
  signal-tile:
    textColor: "{colors.sky}"
    rounded: "{rounded.control}"
    size: "40px"
---

# Design System: SEL Nexus CyberSuite

## Overview

**Creative North Star: "The Night Operations Room"**

A quiet, slate-navy room where the lights are low and only what needs attention glows. The ground is a near-black navy carrying a fixed field of faint dots (22px grid) and one soft blue light falling from the upper right, with a fainter echo in the lower left. Bordered slate panels float on that field with a hairline edge, a catch of light along their top edge and a long soft drop. Nothing shouts except blue (for what you can do) and the severity colours (for what is wrong).

The system serves analysts who read it every day and leaders who see it in demos, so density is moderate: 24px card padding, 16px gutters, a 1400px reading width, tables with generous 14px row padding. Hierarchy comes from weight and tone in a single family (Inter), not from colour. Dark is the default. Light mode is the original beige analytics canvas, kept by request: warm off-white page (#f2f2ef), white flat cards with warm hairlines (#e6e5e0), warm grey text, ink-black (#121212) for primary actions and selection, sky-tinted signal tiles, and no dot field or glow.

The one signature move is the **signal tile**: a rounded square filled with a blue tint, ringed by a blue hairline, lit along its top edge and dropping a soft blue glow. It marks the brand, the active menu item, the sign-in tool areas, the chat header and the floating help-bot button, and nothing else.

**Key Characteristics:**
- Slate-navy ground with a fixed dot field and one blue top light
- Bordered panels with a top-edge highlight and long soft drop
- One blue for actions, selection, links and focus
- Orange, rose, amber, teal and violet reserved for severity, state and chart series
- Inter throughout, tabular figures for every number
- The signal tile as the single signature element

## Colors

A cool slate ladder with one blue voice and a reserved set of state colours. Dark values are canonical (dark is the default theme); light-mode counterparts are recorded in the sidecar. In light mode the `blue` role resolves to ink-black, so "One Blue" reads as "one ink" there.

### Primary
- **Operations Blue** (`blue`): the only action colour. Primary buttons, the selected tab underline, selected filter pills (as a 16% tint with a 55% border), the active menu item's ring, the user avatar, the user's own chat bubbles, and the signal tile's tint and hairline.
- **Lit Blue** (`blue-hi`): hover state for anything solid blue.
- **Sky** (`sky`): blue as text and line. Links, the "CyberSuite" half of the wordmark, the second line of the sign-in headline, signal-tile icons, focus outlines and the text caret.

### Secondary
- **Signal Orange** (`signal`): the first chart series and the severity ramp's family (Critical through Low run from pale to deep orange in dark mode). Used as text only on a signal chip that flags a count; never as a button.

### Tertiary
- **Teal** (`teal`), **Violet** (`violet`), **Amber** (`amber`), **Rose** (`rose`): chart series two to six and state. Rose also marks invalid fields and form errors; violet marks lab-test items.

### Neutral
- **Night Canvas** (`canvas`): the page ground under the dot field; also the top bar at 80% with blur.
- **Slate Panel** (`panel`): cards, the side menu (at 72%), the sign-in card (at 92% with blur), the chat panel.
- **Raised Slate** (`raised`): popovers and menus.
- **Well** (`well`): table header rows, chips, hover fills, the bot's chat bubbles.
- **Field** (`field`): text inputs, a step darker than the panel so fields read as recessed.
- **Hairline** (`hairline`) and **Strong Hairline** (`hairline-strong`): every border; strong for inputs and secondary buttons.
- **Ink ladder** (`ink`, `ink-2`, `ink-3`): headings and values, body and labels, supporting text. Checked on the panel at 13.4:1, 9.9:1 and 5.6:1 (dark theme lifted on 2026-10-13 so sections read apart).

### Named Rules
**The One Blue Rule.** If it can be clicked to act or it is selected, it is blue; nothing else is. Severity and series colours never appear on buttons, links or selection.

**The Colour Follows the Entity Rule.** A chart series keeps its colour across every chart, in the fixed order orange, sky, teal, violet, amber, rose. Text never wears series colours; legend and axis text stay on the ink ladder.

**The State Needs a Word Rule.** Status colours ship with an icon and a label, never as colour alone.

## Typography

**Display Font:** Inter Variable (with Segoe UI, system-ui)
**Body Font:** Inter Variable
**Label/Mono Font:** Inter Variable with tabular figures; no separate mono face.

**Character:** One neutral grotesk carrying everything, with character variants cv11 and ss01 switched on globally. Tight negative tracking on large sizes gives headings a compact, engineered feel; numbers are always tabular.

### Hierarchy
- **Display** (700, 44px rising to 54px at xl, 1.08): sign-in headline only, two lines, the second in sky. Balanced wrapping.
- **Headline** (600, 24px, tight tracking): page titles ("Security overview", "Alert triage"). The sign-in card heading is a larger sibling (700, 28 to 30px, -0.02em).
- **Title** (600, 15px, -0.01em): card titles and sign-in area names.
- **Metric** (400, 34px, line-height 1, tabular): the headline number in a KPI panel. Lighter than the title so the figure reads as data, not as a heading.
- **Body** (400, 14px): table cells, descriptions, menu items. Sign-in fields and lead copy step up to 15px and 18px.
- **Label** (500, 12px): chips, table headers, timestamps; 11px for tags and hop links.

### Named Rules
**The Tabular Figures Rule.** Every number that can change sits in tabular figures so columns and KPIs never jitter.

## Layout

The app is a fixed frame: a 56px translucent top bar, a 256px side menu (64px when collapsed to icons, toggled with Ctrl+B), and a main column capped at 1400px with 24 to 32px side padding and extra right padding (92px on wide screens) that keeps content clear of the floating bot button. Below 1024px the side menu becomes a left sheet (max 300px or 85vw) opened from the top bar.

Pages stack a header (title, one-line description, status pills), tabs with a blue underline, then a grid of panels with 16px gaps: four KPI panels across at xl, two at sm, one on phones. Panels pad 24px (20px for compact KPI tiles); nested item cards inside a panel pad 16px.

Sign-in is a two-column stage at lg and above: a headline column with the four tool areas as a 2x2 grid of signal tiles, and a 580px card. Below lg only the card shows.

## Elevation & Depth

Depth is a hybrid of tone and light. Surfaces step up in tone (canvas, field, panel, raised, well) and every panel carries a hairline border; shadows add a top-edge catch of light and a long, soft drop that lifts the panel off the dot field rather than a hard outline. Glass appears only on the chrome that floats over scrolling content: the top bar, the side menu and the sign-in card.

### Shadow Vocabulary
- **Elev** (`--elev`): every panel at rest. Inset top highlight, a tight contact shadow and a long soft drop.
- **Float** (`--float`): the sign-in card, the chat panel and other surfaces that sit above the page.
- **Blue lift** (on the primary button and signal tile): an inset top highlight plus a soft blue-tinted drop.

### Named Rules
**The Light From Above Rule.** Every raised surface catches light on its top edge (a 1px inset white highlight) and falls into a long soft shadow. No hard, offset or coloured outlines.

## Shapes

Soft, consistent rounding that grows with the surface: 6px chips and tags, 8px icon buttons and secondary buttons, 10px controls (inputs, primary button, menu items, signal tiles), 12px nested cards and tables, 16px floating objects (bot button, chat panel), 20px panels, 24px for the sign-in card. Filter pills and status dots are fully round. Borders are always 1px hairlines; a dashed hairline marks empty states.

## Components

### Buttons
- **Shape:** gently rounded (10px) for the primary; 8px for compact buttons.
- **Primary:** solid Operations Blue, white 15px semibold text, 56px tall and full width in forms, with an inset top highlight and a soft blue drop.
- **Hover / Focus:** background shifts to Lit Blue over 160ms; focus shows a 2px sky outline offset 2px. Disabled drops to 70% opacity.
- **Secondary:** panel fill, strong hairline border, 36px tall ("Run agents"); hover fills with well and tints the border blue.
- **Ghost icon buttons:** 36px square, ink-2 icon, well fill on hover.

### Chips
- **Style:** well fill, hairline border, 12px medium ink-2 text, 6px radius, tabular figures.
- **State:** filter pills are fully round with a hairline border; selected pills take a 16% blue tint, a 55% blue border and ink text.

### Cards / Containers
- **Corner Style:** 20px.
- **Background:** slate panel.
- **Shadow Strategy:** Elev at rest (see Elevation & Depth).
- **Border:** 1px hairline.
- **Internal Padding:** 24px; 15px semibold title with an optional ink-3 description, content 16px below.

### Inputs / Fields
- **Style:** field fill (darker than the panel), strong hairline border, 10px radius, 56px tall in sign-in forms, 15px text, sky caret.
- **Focus:** border turns blue with a 4px blue ring at 15%.
- **Error / Disabled:** rose border and rose ring; errors appear in a rose-tinted box with an icon. Disabled at 60% opacity.

### Navigation
- **Style:** grouped side menu on a translucent panel. Group names are small (11px semibold, uppercase, 0.09em tracking, ink-3) and exist only to organise the menu.
- **Items:** 40px tall, 10px radius, 14px ink-2 text with a 28px icon slot; hover fills with well.
- **Active:** a 10% blue fill with a 25% blue inset ring, ink text, and the icon set in a signal tile.
- **Tabs:** 14px ink-3 text; the selected tab goes ink and medium with a 2px blue underline.
- **Mobile:** the same groups in a left sheet below 1024px.

### Signal Tile (signature)
A rounded square (7 to 16px radius by size) with a blue gradient tint over the panel, a 48% blue hairline, an inset top highlight and a soft blue glow below; the icon is sky. Used for the brand mark (32px), the active menu icon (28px), the sign-in tool areas (40px), the chat header (36px) and the floating bot button (56px, lifts 2px on hover).

### Data Tables
A rounded, hairline-bordered frame with a well-filled header row (12px medium ink-3), hairline row dividers, 10 to 14px cell padding and right-aligned numbers. Severity is a small round dot plus the word.

## Do's and Don'ts

### Do:
- **Do** put every primary action on solid Operations Blue with white text, and nothing else on blue.
- **Do** set every panel on the slate panel colour with a 1px hairline, 20px radius and the Elev shadow.
- **Do** keep the dot field and the blue top light on the page ground; panels sit on it, they do not cover it edge to edge.
- **Do** use the signal tile only for the brand mark, the active menu item, the sign-in tool areas and the help bot.
- **Do** keep numbers in tabular figures and keep text on the ink ladder.
- **Do** pair every status colour with an icon and a label.

### Don't:
- **Don't** use orange, rose, amber, teal or violet for buttons, links or selection; they belong to severity, state and chart series.
- **Don't** put white-on-ink primary buttons or a saturated deep-ocean blue ground in this world; the contract replaced both.
- **Don't** colour chart labels, legends or axis text with series colours.
- **Don't** add hard or offset outlines for depth; use the top-edge highlight and the long soft drop.

## Revision 2026-10-14: "night shift" dark mode with colour-coded areas

The user gave free rein ("dark theme is the main one, blue buttons, other colours allowed"). Page layout unchanged. Replaces the beige light mode, the glass experiment, the blue navigation frame and the "Smart" periwinkle menu; light mode keeps the Smart grey page and white cards.

- **Dark surfaces:** deep indigo-black canvas `#0e1120`, solid cards `#171b2e`, raised `#1d2238`, well `#20263f`, hairlines `#262c46` / `#353d60`; ink `#f2f4fb`, ink-2 `#c4c9de`, ink-3 `#8f96b4` (6.1:1 on a card).
- **One blue for actions:** buttons `#3d6af2` (white on it 4.6:1), hover `#5580ff`; links and focus `#7ea2ff`.
- **Colour-coded areas (signature):** each menu group owns a colour, set as `--area` on its items: Overview blue `#7ea2ff`, Find amber `#fbbf24`, Check rose `#fb7185`, Act teal `#2dd4bf`, Trust & share violet `#a78bfa` (light mode uses deeper cuts: `#3d5bd9`, `#b7791f`, `#d6456b`, `#0f9488`, `#7c5cd6`). Every menu icon sits on a tile tinted with its area colour (`.area-tile`); group headings carry a dot of it. The selected page's row takes a 13% wash and a 34% outline of its area colour and its tile turns solid (`.nav-surface .nav-on`, `.area-tile-on`), so the menu doubles as a map of where you are.
- **Side menu:** a solid panel (`--nav`: dark `#12152a`, light white) with a hairline edge; the top bar sits on the page colour.
- **Chat button and avatar:** solid action blue.
- **Charts (dark):** series orange, blue, teal, violet, amber, rose (`#fb923c`, `#7ea2ff`, `#2dd4bf`, `#a78bfa`, `#fbbf24`, `#fb7185`); blue sequential ramp `#c9d7ff` to `#2f57d6`.

### Update 2026-10-14 (evening): "midnight slate" colour and motion pass

User feedback: "too black and plain; add animations and good colours". Guided by the ui-ux-pro-max design-system search (dark slate base, status colours, stagger entrance).

- **Dark surfaces lifted to slate-navy:** canvas `#131a2c`, cards `#1c2338`, raised `#232b44`, well `#262f4a`, hairlines `#2b3450` / `#3a4568`; ink `#f1f4fb` / `#c5cce0` / `#969fbc`; links `#82a8ff`. Area colours and the action blue are unchanged.
- **Side menu (dark):** a deep blue-to-indigo gradient (`#1b2556` to `#1d1b47`) behind the colour-coded area tiles.
- **Brand stripe:** a 3px line across the top of the screen running through the five area colours (`.brand-stripe`).
- **Colour washes:** soft blue, violet and teal light behind the dark page (`body::before`), drifting over 28s; solid colour, no blur.
- **Motion:** cards rise into place when a page opens (520ms, expo-out, siblings staggered 60ms, `card-in`); menu icon tiles spring slightly on hover; blue buttons lift 1px on hover and press to 98% on click. Everything is off under `prefers-reduced-motion`.

### Update 2026-10-14 (late): "electric" (user reference: dark finance dashboard)

Supersedes the midnight-slate colours above; layout, motion and the colour-coded menu areas stay.

- **Dark surfaces:** neutral charcoal, not navy: canvas `#0c0e13`, cards `#15171e` (flat, thin `#252932` border that brightens to `#343945` on hover), raised `#1b1e26`, well `#1f232c`; ink `#f5f7fb` / `#c7ccd6` / `#8b919e`; links `#6b97ff`.
- **Electric blue is the major colour:** `#1d5cff` (hover `#3b74ff`) for buttons, the selected menu tile (solid blue square, white icon), the chat button, the first chart series and the hero card. Light mode uses the same blue (hover `#1747d1`).
- **Supporting colours:** green `#22c55e` (good, healthy, Act area), yellow `#facc15` (warnings, Find area), violet `#8b5cf6` (Trust area), rose `#f43f5e` (Check area), orange `#f97316` (signal). Light mode uses deeper cuts (`#16a34a`, `#ca8a04`/`#b45309`, `#7c3aed`, `#e11d48`).
- **Hero card (signature):** each overview page's headline number sits on a solid electric-blue card with a lighter curved band in its lower right (`.card-hero`; theme colours remapped to white inside it): Dashboard "Priority 1 findings", Alert triage "Incidents triaged", Vulnerabilities "Open findings".
- **Charts:** series blue, green, yellow, violet, orange, rose; electric-blue sequential ramp; severity colours unchanged.
- **Side menu:** charcoal `#101217` (dark) / white (light); top stripe is a 2px blue-to-green line; one faint blue light behind the page.

### Update 2026-10-14 (night): solid colours only, richer charts

User feedback: "solid colours only, no glass effects; more colours and better graphs".

- **No translucent tints anywhere in the chrome:** menu icon tiles are solid area colours with a contrasting icon (`--area-*-on`: white on blue/rose/violet, near-black on yellow/green); the selected menu row is a solid blue bar with white text and a white tile; the brand and sign-in tiles are solid blue; selected filter pills are solid blue with white text; the light washes behind the page are gone.
- **Charts (shared in `components/Chart.tsx`):** an 8-colour palette (blue, green, yellow, purple, orange, cyan, rose, pink); bars get rounded tops and a 34px max width; lines are smooth with a colour fade underneath; doughnuts get rounded, separated slices; dashed gridlines; a 900ms eased entrance. A chart that sets any of these itself keeps its own value.
- **Sequential ramp is multi-hue:** blue → violet → magenta, light = low, deep = high (treemap, funnel, heat), so ordering still reads while adding colour.
- **Dashboard ranking:** each app's bar has its own palette colour, is thicker (10px), and grows in from the left (staggered 40ms; off under reduced motion).

### Update 2026-10-15: clearer cards, navy side menu

- **Cards stand off the page more (dark):** canvas `#0a0b10`, cards `#1a1e28` with `#2f3544` borders and a soft drop (`0 14px 32px -18px`), raised `#212532`, well `#252a37`, strong hairline `#3f4656`; ink-2 `#cbd0da`, ink-3 `#959caa`. Light mode cards get a slightly stronger drop.
- **Side menu is a dark blue-black panel in both themes:** `--nav: #0e1631` with a subtle vertical gradient (`#111b3b` to `#0b1128`), a 1px blue edge line on its right (`rgb(59 116 255 / 0.55)`) and a soft shadow, so it reads as navigation and not as page. Inside it text is white, headings `#a9b6dc`, dividers and hovers are pale-blue alpha. The selected page is a solid blue pill (`#1d5cff`) with white text and a white tile carrying the blue icon; the other icons keep their solid area colours.
- A bright royal-blue menu was tried and rejected by the user in favour of this navy.

### Update 2026-10-15 (later): one continuous blue-black space, coloured icons without boxes

User feedback: "the navbar looks like a different part; make the whole app that dark blue-black, pitch black allowed, cards must look good; make the icons themselves coloured, remove the coloured boxes".

- **Dark ground everywhere:** page `#05070d`, side menu `#060912`, top bar on the page colour. The menu is separated only by a hairline, so it reads as part of the same space. Light mode's menu is white again for the same reason.
- **Bluish cards:** `#0e1424` with a faint top-lit gradient from `#111829`, borders `#1d2740` (hover `#2c3857`), raised `#141b2e`, well `#151d33`; ink `#eef2fb` / `#bcc6dd` / `#8792b0` (5.7:1 on a card). The blue hero card is excluded from the card gradient (`:not(.card-hero)`).
- **Menu icons:** drawn in their area colour with no tile behind them (blue `#5b8cff`, yellow, rose, green, violet in dark; deeper cuts in light). They scale up slightly on hover. The selected page stays a solid blue pill with white text and a white icon.

### Update 2026-10-16: coloured count cards and tinted boxes

- **Count cards in solid colours** (`.card-hero` plus `.card-hero-red / -orange / -green / -violet / -amber`; blue is the default), each a top-lit gradient of one hue with a lighter curved band, deep enough for white text at 4.5:1 or better. Colour follows meaning:
  - Vulnerabilities: Open findings blue, Critical red, Priority 1 orange, Devices affected green, Apps to update violet.
  - Alert triage: Incidents triaged blue, True positive red, False positive green, Needs review amber.
- **Tinted boxes inside a card** (`.tint-box` with `--tint`): a solid mix of 16% hue into the card colour, a 42% hue border and a number in a light cut of the hue. Used for the three Threat news posture boxes: threats collected blue, clues collected violet, threats affect us red. Tint tokens `--tint-blue / -violet / -red` per theme.
