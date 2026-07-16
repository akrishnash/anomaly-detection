---
name: Obsidian Sentinel
colors:
  surface: '#131313'
  surface-dim: '#131313'
  surface-bright: '#3a3939'
  surface-container-lowest: '#0e0e0e'
  surface-container-low: '#1c1b1b'
  surface-container: '#201f1f'
  surface-container-high: '#2a2a2a'
  surface-container-highest: '#353534'
  on-surface: '#e5e2e1'
  on-surface-variant: '#b9cacb'
  inverse-surface: '#e5e2e1'
  inverse-on-surface: '#313030'
  outline: '#849495'
  outline-variant: '#3b494b'
  surface-tint: '#00dbe9'
  primary: '#dbfcff'
  on-primary: '#00363a'
  primary-container: '#00f0ff'
  on-primary-container: '#006970'
  inverse-primary: '#006970'
  secondary: '#d1bcff'
  on-secondary: '#3c0090'
  secondary-container: '#7000ff'
  on-secondary-container: '#ddcdff'
  tertiary: '#f4f5ff'
  on-tertiary: '#002e6a'
  tertiary-container: '#cad9ff'
  on-tertiary-container: '#005ac3'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#7df4ff'
  primary-fixed-dim: '#00dbe9'
  on-primary-fixed: '#002022'
  on-primary-fixed-variant: '#004f54'
  secondary-fixed: '#e9ddff'
  secondary-fixed-dim: '#d1bcff'
  on-secondary-fixed: '#23005b'
  on-secondary-fixed-variant: '#5700c9'
  tertiary-fixed: '#d8e2ff'
  tertiary-fixed-dim: '#adc6ff'
  on-tertiary-fixed: '#001a42'
  on-tertiary-fixed-variant: '#004395'
  background: '#131313'
  on-background: '#e5e2e1'
  surface-variant: '#353534'
typography:
  display-lg:
    fontFamily: Geist
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-lg-mobile:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-md:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  body-lg:
    fontFamily: Geist
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 22px
  label-mono:
    fontFamily: Space Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.05em
  label-caps:
    fontFamily: Geist
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 14px
    letterSpacing: 0.1em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  unit: 4px
  container-max: 1440px
  gutter: 24px
  margin-mobile: 16px
  margin-desktop: 48px
  panel-gap: 16px
---

## Brand & Style
The brand personality is authoritative, vigilant, and cutting-edge. It targets cybersecurity professionals who require high-density information environments that remain legible and calm under pressure. The emotional response is one of "ordered complexity"—feeling like a powerful command center that is both futuristic and deeply reliable.

The design style is a **Sophisticated Cyber-Glassmorphism**. It blends the technical precision of developer-centric tools with a premium, high-fidelity aesthetic. It utilizes deep layering, background blurs, and localized neon accents to guide the eye toward critical security alerts without overwhelming the user.

## Colors
This design system utilizes a "Deep Space" palette. The foundation is **Obsidian (#050505)** for base backgrounds to maximize contrast with glowing elements. 

- **Primary (Electric Cyan):** Used for primary actions, active states, and high-priority data points.
- **Secondary (Neon Purple):** Used for analytical overlays and secondary branding elements.
- **Surface Strategy:** Surfaces use **Charcoal (#121212)** with varying levels of transparency (60-80%) to facilitate the glassmorphism effect.
- **Glows:** Use 20% opacity versions of the accent colors for soft radial background blurs behind key modules to imply "energy" and system activity.

## Typography
The system uses **Geist** for its exceptional clarity and technical "developer" feel. It is paired with **Space Mono** specifically for metadata, timestamps, and IP addresses to reinforce the cybersecurity context.

- **Headlines:** Should be tightly tracked and bold to feel like impactful declarations.
- **Body:** Prioritize legibility. Use `body-md` as the standard for data grids.
- **Labels:** Use `label-mono` for all system-generated strings (hashes, IDs). Use `label-caps` for table headers and small section titles.

## Layout & Spacing
The layout follows a **Fluid Grid** model with high-density spacing. Elements are organized into modular "panels" that behave like floating glass panes.

- **Grid:** 12-column system for desktop, 4-column for mobile.
- **Rhythm:** Based on a 4px baseline. Most component spacing (padding/margins) should use multiples of 4 (8, 16, 24, 32).
- **Density:** High. Vertical spacing between dashboard modules is kept at 16px to allow more data to be visible above the fold.
- **Safe Areas:** On desktop, use a 48px outer margin to give the "floating" UI room to breathe against the obsidian background.

## Elevation & Depth
Elevation is not conveyed through traditional black shadows, but through **Tonal Layering** and **Luminescence**.

1. **Base:** Obsidian (#050505) - The bottom-most layer.
2. **Floor:** Charcoal (#121212) - Used for sidebar and navigation backgrounds.
3. **Glass Panel (Elevation 1):** Background: `rgba(18, 18, 18, 0.7)`. Backdrop Filter: `blur(12px)`. Border: `1px solid rgba(255, 255, 255, 0.08)`.
4. **Active State (Elevation 2):** Same as above, but with a primary color border gradient and a 4px "Neon Glow" (`box-shadow: 0 0 15px rgba(0, 240, 255, 0.15)`).

Use thin, 1px borders for all containers to maintain a "wireframe-precise" look.

## Shapes
The design system uses a specific 18px radius for main containers to create a modern, "hardware-inspired" look.

- **Main Panels:** 18px (`rounded-xl` / 1.5rem).
- **Buttons & Inputs:** 8px (`rounded-md` / 0.5rem) for a more technical, sharp feel.
- **Status Tags:** Fully rounded (Pill) to differentiate from interactive buttons.

## Components

### Buttons
- **Primary:** Solid Cyan background, black text. Transition: Add a cyan outer glow on hover.
- **Secondary:** Ghost style. Transparent background, 1px white (10% opacity) border. White text.
- **Tertiary/Icon:** No border, semi-transparent white text.

### Floating Statistics Cards
Large `display-lg` numbers. Top-right corner features a "Sparkline" graph in the accent color. The card itself uses the Elevation 1 Glass panel style.

### Glowing Status Indicators
Small circular dots.
- `Critical`: Red pulse animation using a 10px radial glow.
- `Active`: Steady Cyan glow.
- `Idle`: Dim grey, no glow.

### Input Fields
Darker than the panel background (#0A0A0A). Borders are only visible on the bottom or as a subtle 1px surround. On focus, the border transitions to a Cyan-to-Purple gradient.

### Lists & Data Grids
Rows are separated by `1px solid rgba(255, 255, 255, 0.04)`. Hovering over a row should apply a subtle light-grey highlight (5% opacity) and change the text of the primary column to Cyan.

### Additional Components
- **Terminal View:** A dedicated code-block style container with mono font for raw log inspection.
- **Threat Map:** A stylized vector map with localized "heat" glows for geographic attacks.