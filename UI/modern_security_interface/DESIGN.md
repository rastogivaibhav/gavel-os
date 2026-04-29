---
name: Modern Security Interface
colors:
  surface: '#f9f9ff'
  surface-dim: '#cfdaf2'
  surface-bright: '#f9f9ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f0f3ff'
  surface-container: '#e7eeff'
  surface-container-high: '#dee8ff'
  surface-container-highest: '#d8e3fb'
  on-surface: '#111c2d'
  on-surface-variant: '#3d4a42'
  inverse-surface: '#263143'
  inverse-on-surface: '#ecf1ff'
  outline: '#6d7a72'
  outline-variant: '#bccac0'
  surface-tint: '#006c4a'
  primary: '#006948'
  on-primary: '#ffffff'
  primary-container: '#00855d'
  on-primary-container: '#f5fff7'
  inverse-primary: '#68dba9'
  secondary: '#505f76'
  on-secondary: '#ffffff'
  secondary-container: '#d0e1fb'
  on-secondary-container: '#54647a'
  tertiary: '#00628d'
  on-tertiary: '#ffffff'
  tertiary-container: '#007cb1'
  on-tertiary-container: '#fcfcff'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#85f8c4'
  primary-fixed-dim: '#68dba9'
  on-primary-fixed: '#002114'
  on-primary-fixed-variant: '#005137'
  secondary-fixed: '#d3e4fe'
  secondary-fixed-dim: '#b7c8e1'
  on-secondary-fixed: '#0b1c30'
  on-secondary-fixed-variant: '#38485d'
  tertiary-fixed: '#c9e6ff'
  tertiary-fixed-dim: '#89ceff'
  on-tertiary-fixed: '#001e2f'
  on-tertiary-fixed-variant: '#004c6e'
  background: '#f9f9ff'
  on-background: '#111c2d'
  surface-variant: '#d8e3fb'
typography:
  display-xl:
    fontFamily: Space Grotesk
    fontSize: 36px
    fontWeight: '700'
    lineHeight: '1.2'
    letterSpacing: -0.02em
  display-lg:
    fontFamily: Space Grotesk
    fontSize: 30px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Space Grotesk
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.3'
  title-sm:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: '1.5'
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: '1.6'
  body-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: '1.5'
  label-caps:
    fontFamily: Space Grotesk
    fontSize: 12px
    fontWeight: '700'
    lineHeight: '1'
    letterSpacing: 0.05em
  mono-data:
    fontFamily: Space Grotesk
    fontSize: 14px
    fontWeight: '500'
    lineHeight: '1.4'
    letterSpacing: -0.01em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 8px
  container-margin: 32px
  gutter: 24px
  component-padding-x: 16px
  component-padding-y: 10px
  stack-sm: 8px
  stack-md: 16px
  stack-lg: 32px
---

## Brand & Style

This design system is engineered for high-stakes enterprise security environments where cognitive load must be minimized without sacrificing data density. The aesthetic is **Corporate / Modern** with a strong influence from **Minimalism**, prioritizing "command center" precision and immediate information retrieval.

The brand personality is vigilant, professional, and transparent. By utilizing a high-clarity light mode, the interface moves away from the "hacker" tropes of dark themes toward a sophisticated, institutional reliability. It evokes a sense of calm authority through ample whitespace, rigid structural alignment, and a curated accent palette that directs attention to critical status changes.

## Colors

The color strategy for this design system relies on a "Chrome and Content" logic. The "Chrome" (the interface shell) uses **Subtle Slates (#F8FAFC)** and **Pure Whites (#FFFFFF)** to create a canvas that feels expansive and clean. 

**Deep Emerald (#059669)** serves as the primary action and "secure" state color, chosen for its high legibility against light backgrounds compared to standard bright greens. **Dark Slate (#1E293B)** provides high-contrast typography for maximum readability. For data visualization and status indicators, the palette extends to include a technical blue for information and a sharp red/amber for critical alerts, ensuring that the "command center" can communicate urgency through color-coding without overwhelming the user.

## Typography

This design system utilizes a dual-font strategy to balance technical precision with readability. 

**Space Grotesk** is used for headlines, display metrics, and labels. Its geometric, slightly mechanical nature reinforces the technical "command center" feel. It is particularly effective for numerical data and uppercase labels, providing a distinct visual signature for the dashboard's structure.

**Inter** is the workhorse for all body copy, inputs, and descriptions. Chosen for its neutral, systematic clarity and exceptional legibility at small sizes, it ensures that complex security logs and documentation remain easy to parse during long periods of monitoring.

## Layout & Spacing

The layout follows a **Fluid Grid** philosophy to accommodate the wide variety of screen sizes used in SOC (Security Operations Center) environments. The dashboard uses a 12-column grid system with 24px gutters, allowing for modular "widgets" that can span 3, 4, 6, or 12 columns depending on data complexity.

A strict 8px spacing rhythm governs all element relationships. Margins are generous (32px) to prevent the UI from feeling claustrophobic, while internal component spacing is kept tight to maintain high data density. Elements should be aligned to a rigid baseline to emphasize the feeling of mathematical precision and order.

## Elevation & Depth

To maintain a "high-clarity" aesthetic, this design system avoids heavy drop shadows and dramatic depth. Instead, it utilizes **Tonal Layers** and **Low-contrast Outlines**.

Depth is communicated through color: the main background is #F8FAFC, while primary cards and interactive containers are #FFFFFF. These surfaces are defined by a crisp 1px border in #E2E8F0. 

For active states (such as a selected card or an open modal), a very soft, diffused ambient shadow with a 10% opacity slate tint may be used to provide subtle focus. This approach ensures the interface remains "flat" enough to feel fast and lightweight, but layered enough to indicate hierarchy.

## Shapes

The shape language is **Soft (Level 1)**. Standard UI elements like buttons, input fields, and chips use a 0.25rem (4px) corner radius. Larger containers and cards use a 0.5rem (8px) radius.

This subtle rounding strikes a balance between the "sharpness" of traditional technical software and the "friendliness" of modern SaaS. It maintains a professional, disciplined appearance that feels engineered rather than organic. Icons should follow this logic, using a consistent 1.5pt stroke weight and slightly rounded caps to match the UI's geometry.

## Components

### Buttons
Primary buttons use a solid Deep Emerald (#059669) fill with white text. Secondary buttons use a white background with the slate border (#E2E8F0) and dark text. Interactions should be subtle—a slight darkening of the background on hover.

### Status Chips
Critical for security, chips use a light background tint of their status color with high-contrast text (e.g., a "Critical" chip has a light red background and dark red text). They use the `label-caps` typography for immediate recognition.

### Data Tables
The core of the dashboard. Tables use a minimal design with no vertical borders. Horizontal borders are 1px #E2E8F0. Row headers use `title-sm` while data cells use `mono-data` for alignment precision.

### Input Fields
Inputs are white with a slate border. When focused, the border transitions to Deep Emerald with a subtle 2px outer glow of the same color at 20% opacity.

### Security Widgets (Cards)
Cards serve as the primary container for data visualizations. They must include a `headline-md` title, a consistent 24px internal padding, and use the #FFFFFF background to pop against the #F8FAFC canvas.

### Activity Feed
A specialized component using vertical lines to connect chronological events, emphasizing the "command center" timeline of security incidents.