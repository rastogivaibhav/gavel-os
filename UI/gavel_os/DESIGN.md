---
name: GAVEL OS
colors:
  surface: '#13131b'
  surface-dim: '#13131b'
  surface-bright: '#393841'
  surface-container-lowest: '#0d0d15'
  surface-container-low: '#1b1b23'
  surface-container: '#1f1f27'
  surface-container-high: '#292932'
  surface-container-highest: '#34343d'
  on-surface: '#e4e1ed'
  on-surface-variant: '#c7c4d7'
  inverse-surface: '#e4e1ed'
  inverse-on-surface: '#303038'
  outline: '#908fa0'
  outline-variant: '#464554'
  surface-tint: '#c0c1ff'
  primary: '#c0c1ff'
  on-primary: '#1000a9'
  primary-container: '#8083ff'
  on-primary-container: '#0d0096'
  inverse-primary: '#494bd6'
  secondary: '#bdc7d9'
  on-secondary: '#27313f'
  secondary-container: '#404a59'
  on-secondary-container: '#afb9cb'
  tertiary: '#ffb783'
  on-tertiary: '#4f2500'
  tertiary-container: '#d97721'
  on-tertiary-container: '#452000'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#e1e0ff'
  primary-fixed-dim: '#c0c1ff'
  on-primary-fixed: '#07006c'
  on-primary-fixed-variant: '#2f2ebe'
  secondary-fixed: '#d9e3f6'
  secondary-fixed-dim: '#bdc7d9'
  on-secondary-fixed: '#121c2a'
  on-secondary-fixed-variant: '#3d4756'
  tertiary-fixed: '#ffdcc5'
  tertiary-fixed-dim: '#ffb783'
  on-tertiary-fixed: '#301400'
  on-tertiary-fixed-variant: '#703700'
  background: '#13131b'
  on-background: '#e4e1ed'
  surface-variant: '#34343d'
typography:
  h1:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: -0.02em
  h2:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.3'
    letterSpacing: -0.01em
  h3:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: '1.4'
    letterSpacing: '0'
  body:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: '1.5'
    letterSpacing: '0'
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: '1.5'
    letterSpacing: '0'
  label:
    fontFamily: Space Grotesk
    fontSize: 11px
    fontWeight: '500'
    lineHeight: '1'
    letterSpacing: 0.05em
  mono:
    fontFamily: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas
    fontSize: 13px
    fontWeight: '400'
    lineHeight: '1.6'
    letterSpacing: '0'
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  gutter: 16px
  margin: 24px
---

## Brand & Style

The design system is engineered for high-stakes enterprise AI governance, where clarity, authority, and technical precision are paramount. The aesthetic is **Corporate Modern** with a heavy influence from **Command Center** aesthetics, prioritizing data density and rapid cognitive processing. It evokes the feeling of a mission-critical security cockpit—serious, reliable, and premium.

The target audience consists of AI engineers, compliance officers, and security architects. The UI avoids decorative elements in favor of functional aesthetics, utilizing subtle borders and monochromatic layering to create a sense of deep, organized architecture. The overall atmosphere is focused and steady, providing a "calm-in-the-storm" experience for managing complex AI risk.

## Colors

The palette is anchored in a "Midnight Navy" spectrum to reduce eye strain during prolonged monitoring sessions. 

- **Foundational Layers:** The background (#0B1020) provides a deep void that makes the surface containers (#111827) appear to float slightly above it. 
- **Accents:** The primary Indigo (#6366F1) is used sparingly for active states and primary actions, ensuring it acts as a beacon rather than a distraction.
- **Semantic Logic:** Status colors (Success, Warning, Danger) utilize high-vibrancy tones to cut through the dark UI, ensuring critical system alerts are immediately visible.
- **Borders:** A refined border color (#293548) is used to define structure without creating high-contrast visual noise.

## Typography

This design system utilizes **Inter** for its systematic, utilitarian clarity in all primary UI roles. For technical data and high-level metadata, **Space Grotesk** is introduced as a label font to provide a subtle "futuristic/technical" edge that differentiates GAVEL OS from standard SaaS applications.

- **Scale:** A tight, efficient type scale is maintained to maximize data density.
- **Monospace:** Reserved for code blocks, AI logs, and policy definitions.
- **Hierarchy:** Established through weight shifts (600 for headers, 400 for body) rather than dramatic size changes, maintaining a professional and understated tone.

## Layout & Spacing

The design system employs a **Fluid Grid** model designed to adapt across wide-screen monitoring displays. 

- **Grid:** A 12-column layout with 16px gutters allows for modular dashboard construction. 
- **Density:** The spacing rhythm is based on a 4px baseline, but defaults to a "compact" density to ensure technical tables and policy editors display maximum information without scrolling.
- **Logic:** Padding within cards should be consistent (16px), while external margins between major UI sections should be 24px to provide clear visual separation between distinct control modules.

## Elevation & Depth

Elevation is achieved through **Tonal Layers** and **Low-Contrast Outlines** rather than traditional drop shadows.

- **Surface Tiering:** The deepest level is the Background (#0B1020). Secondary surfaces and cards use the Surface color (#111827). Hover states or active popovers use the Secondary color (#1F2937).
- **Ghost Borders:** Every container must have a 1px solid border (#293548). This creates a "blueprint" effect that defines structure in a low-light environment.
- **Shadows:** Only used for floating modals or context menus, utilizing a dark, highly diffused shadow (#000000, 40% opacity, 20px blur) to prevent the "floating" element from feeling disconnected from the technical grid.

## Shapes

The design system utilizes **Soft** roundedness. While the tone is technical, sharp 0px corners are avoided to ensure the interface feels modern and "designed" rather than purely skeletal.

- **Standard Elements:** Cards, buttons, and input fields use a 4px (0.25rem) radius.
- **Large Elements:** Modals and large dashboard panels use an 8px (0.5rem) radius.
- **Tags/Status:** Badge chips and status indicators use a fully rounded (pill) shape to distinguish them from structural UI elements and buttons.

## Components

- **Buttons:** Primary buttons use the Indigo background with white text. Secondary buttons are ghost-style with the Border color and a subtle hover fill.
- **Cards:** Defined by a 1px border (#293548) and the Surface background (#111827). Card headers should have a subtle bottom border to separate the title from the content.
- **Technical Tables:** Minimalist design with no vertical borders. Row headers use 500 weight. Row hover states should use a subtle background shift to #1F2937.
- **Badge Chips:** Low-saturation backgrounds with high-saturation text (e.g., a dark green background with bright green text) for status indicators like "Compliant" or "Shielded."
- **Status Dots:** 8px circles used in tables to indicate real-time AI system health.
- **Monaco Editor:** The core of the governance plane. It should be embedded with a custom theme matching the Surface and Indigo palette, utilizing the defined Monospace font for policy authoring.
- **Breadcrumbs & Steps:** Minimalist text-based navigation using the Label typography style to keep the focus on the current task.