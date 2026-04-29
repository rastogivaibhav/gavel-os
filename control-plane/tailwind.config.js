/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './static/pages/**/*.html',
    './static/js/**/*.js',
  ],
  theme: {
    extend: {
      colors: {
        'surface-dim': '#cfdaf2',
        'on-error-container': '#93000a',
        'secondary-fixed-dim': '#b7c8e1',
        'on-tertiary-fixed': '#001e2f',
        'surface-tint': '#006c4a',
        'on-primary': '#ffffff',
        'tertiary-fixed-dim': '#89ceff',
        'on-tertiary': '#ffffff',
        'on-background': '#111c2d',
        'error-container': '#ffdad6',
        'surface-container-lowest': '#ffffff',
        'surface': '#f9f9ff',
        'surface-variant': '#d8e3fb',
        'surface-container-high': '#dee8ff',
        'on-tertiary-fixed-variant': '#004c6e',
        'primary-container': '#00855d',
        'on-primary-container': '#f5fff7',
        'secondary-container': '#d0e1fb',
        'on-surface': '#111c2d',
        'on-primary-fixed-variant': '#005137',
        'background': '#f9f9ff',
        'inverse-on-surface': '#ecf1ff',
        'surface-container-low': '#f0f3ff',
        'secondary': '#505f76',
        'outline': '#6d7a72',
        'on-secondary-container': '#54647a',
        'primary-fixed-dim': '#68dba9',
        'on-primary-fixed': '#002114',
        'surface-container': '#e7eeff',
        'on-secondary-fixed': '#0b1c30',
        'on-tertiary-container': '#fcfcff',
        'on-secondary': '#ffffff',
        'primary': '#006948',
        'outline-variant': '#bccac0',
        'error': '#ba1a1a',
        'on-error': '#ffffff',
        'primary-fixed': '#85f8c4',
        'tertiary': '#00628d',
        'surface-container-highest': '#d8e3fb',
        'secondary-fixed': '#d3e4fe',
        'surface-bright': '#f9f9ff',
        'on-surface-variant': '#3d4a42',
        'tertiary-fixed': '#c9e6ff',
        'inverse-surface': '#263143',
        'tertiary-container': '#007cb1',
        'on-secondary-fixed-variant': '#38485d',
        'inverse-primary': '#68dba9'
      },
      borderRadius: {
        'DEFAULT': '0.125rem',
        'lg': '0.25rem',
        'xl': '0.5rem',
        'full': '0.75rem'
      },
      spacing: {
        'unit': '8px',
        'stack-lg': '32px',
        'container-margin': '32px',
        'gutter': '24px',
        'component-padding-x': '16px',
        'component-padding-y': '10px',
        'stack-sm': '8px',
        'stack-md': '16px'
      },
      fontFamily: {
        'title-sm': ['Inter'],
        'display-lg': ['Space Grotesk'],
        'display-xl': ['Space Grotesk'],
        'label-caps': ['Space Grotesk'],
        'body-sm': ['Inter'],
        'headline-md': ['Space Grotesk'],
        'mono-data': ['Space Grotesk'],
        'body-md': ['Inter']
      },
      fontSize: {
        'title-sm': ['18px', { lineHeight: '1.5', fontWeight: '600' }],
        'display-lg': ['30px', { lineHeight: '1.2', letterSpacing: '-0.01em', fontWeight: '600' }],
        'display-xl': ['36px', { lineHeight: '1.2', letterSpacing: '-0.02em', fontWeight: '700' }],
        'label-caps': ['12px', { lineHeight: '1', letterSpacing: '0.05em', fontWeight: '700' }],
        'body-sm': ['14px', { lineHeight: '1.5', fontWeight: '400' }],
        'headline-md': ['24px', { lineHeight: '1.3', fontWeight: '600' }],
        'mono-data': ['14px', { lineHeight: '1.4', letterSpacing: '-0.01em', fontWeight: '500' }],
        'body-md': ['16px', { lineHeight: '1.6', fontWeight: '400' }]
      }
    }
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
