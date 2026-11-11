import type { CSSProperties } from 'react';
import { createTheme } from '@mui/material/styles';

/*
 * The record book with an instrument's data: warm paper and dark ink by day,
 * a lamplit page at night. Sentences and headings are in a serif face, data
 * (fingerprints, commands, dates) in a monospace face. One accent, the
 * blue-black of a fountain pen. Severity has four colours that mean nothing
 * else, and it is never colour alone: a shape and a word come with it
 * (ui/Glyph.tsx).
 *
 * Every size and colour the screens use is defined here; the screens do
 * layout with Tailwind and take their colours from the tokens in index.css.
 * The smallest text on the page is 0.75rem (12px).
 */

export interface SeverityPalette {
  critical: string;
  alert: string;
  notice: string;
  info: string;
  ok: string;
}

declare module '@mui/material/styles' {
  interface Palette {
    severity: SeverityPalette;
    sunk: string;
    rule: string;
  }
  interface PaletteOptions {
    severity?: SeverityPalette;
    sunk?: string;
    rule?: string;
  }
  interface TypographyVariants {
    data: CSSProperties;
  }
  interface TypographyVariantsOptions {
    data?: CSSProperties;
  }
}

declare module '@mui/material/Typography' {
  interface TypographyPropsVariantOverrides {
    data: true;
  }
}

export const SERIF = 'var(--ritueel-serif)';
export const MONO = 'var(--ritueel-mono)';

/** The smallest text size, in rem. A test keeps every size in the source at or above it. */
export const MIN_TEXT_REM = 0.75;

export const theme = createTheme({
  cssVariables: { colorSchemeSelector: 'data' },
  colorSchemes: {
    light: {
      palette: {
        mode: 'light',
        primary: { main: '#23476a', dark: '#16314b', light: '#5b7e9f', contrastText: '#fbf8ef' },
        error: { main: '#9a2b22' },
        warning: { main: '#8a4f08' },
        info: { main: '#5e3f86' },
        success: { main: '#2c6b3e' },
        background: { default: '#f3eee2', paper: '#faf7ef' },
        text: { primary: '#1f1c17', secondary: '#5a523f' },
        divider: '#cfc4a8',
        sunk: '#ebe4d3',
        rule: '#3a352b',
        severity: { critical: '#9a2b22', alert: '#8a4f08', notice: '#5e3f86', info: '#5a523f', ok: '#2c6b3e' },
      },
    },
    dark: {
      palette: {
        mode: 'dark',
        primary: { main: '#8db3d8', dark: '#6a93b9', light: '#b3cde6', contrastText: '#10151a' },
        error: { main: '#ec8a7a' },
        warning: { main: '#dba654' },
        info: { main: '#c3a1e6' },
        success: { main: '#7fcf96' },
        background: { default: '#151410', paper: '#1d1b16' },
        text: { primary: '#eae4d4', secondary: '#b0a78f' },
        divider: '#4a4537',
        sunk: '#100f0c',
        rule: '#c9c0a8',
        severity: { critical: '#ec8a7a', alert: '#dba654', notice: '#c3a1e6', info: '#b0a78f', ok: '#7fcf96' },
      },
    },
  },
  shape: { borderRadius: 2 },
  breakpoints: { values: { xs: 0, sm: 600, md: 900, lg: 1100, xl: 1536 } },
  typography: {
    fontFamily: SERIF,
    fontSize: 16,
    htmlFontSize: 16,
    h1: { fontFamily: SERIF, fontWeight: 500, fontSize: 'clamp(1.75rem, 1.3rem + 1.8vw, 2.5rem)', lineHeight: 1.12, letterSpacing: '-0.012em' },
    h2: { fontFamily: SERIF, fontWeight: 600, fontSize: '1.3rem', lineHeight: 1.2 },
    h3: { fontFamily: SERIF, fontWeight: 700, fontSize: '1.125rem', lineHeight: 1.3 },
    h4: { fontFamily: SERIF, fontWeight: 700, fontSize: '1rem', lineHeight: 1.35 },
    body1: { fontSize: '1rem', lineHeight: 1.55 },
    body2: { fontSize: '0.9375rem', lineHeight: 1.5 },
    overline: { fontFamily: MONO, fontWeight: 600, fontSize: `${MIN_TEXT_REM}rem`, letterSpacing: '0.08em', lineHeight: 1.4, textTransform: 'uppercase' },
    caption: { fontFamily: SERIF, fontSize: '0.8125rem', lineHeight: 1.45 },
    button: { fontFamily: SERIF, fontWeight: 700, fontSize: '0.9375rem', textTransform: 'none', letterSpacing: '0.005em' },
    data: { fontFamily: MONO, fontSize: '0.8125rem', lineHeight: 1.5 },
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: { fontVariantNumeric: 'lining-nums', WebkitTextSizeAdjust: '100%' },
        'code, kbd, samp, pre': { fontFamily: MONO },
        '::selection': { background: 'var(--mui-palette-primary-main)', color: 'var(--mui-palette-primary-contrastText)' },
      },
    },
    MuiButtonBase: { defaultProps: { disableRipple: true } },
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: {
        root: { borderRadius: 2, paddingInline: '1rem', minHeight: 44 },
        outlined: ({ theme }) => ({
          color: theme.vars.palette.text.primary,
          borderColor: theme.vars.palette.rule,
          '&:hover': { borderColor: theme.vars.palette.primary.main, backgroundColor: theme.vars.palette.sunk },
        }),
        text: ({ theme }) => ({ color: theme.vars.palette.primary.main, '&:hover': { backgroundColor: theme.vars.palette.sunk } }),
      },
    },
    MuiToggleButtonGroup: { defaultProps: { size: 'small' } },
    MuiToggleButton: {
      styleOverrides: {
        root: ({ theme }) => ({
          textTransform: 'none',
          fontFamily: SERIF,
          fontWeight: 700,
          fontSize: '0.875rem',
          minHeight: 44,
          paddingInline: '0.9rem',
          color: theme.vars.palette.text.primary,
          borderColor: theme.vars.palette.rule,
          '&.Mui-selected': {
            color: theme.vars.palette.primary.contrastText,
            backgroundColor: theme.vars.palette.primary.main,
            '&:hover': { backgroundColor: theme.vars.palette.primary.dark },
          },
        }),
      },
    },
    MuiLink: { defaultProps: { underline: 'always' } },
    MuiTooltip: {
      styleOverrides: {
        tooltip: ({ theme }) => ({
          fontFamily: SERIF,
          fontSize: '0.8125rem',
          borderRadius: 2,
          backgroundColor: theme.vars.palette.text.primary,
          color: theme.vars.palette.background.default,
        }),
        arrow: ({ theme }) => ({ color: theme.vars.palette.text.primary }),
      },
    },
    MuiPopover: {
      styleOverrides: {
        paper: ({ theme }) => ({
          borderRadius: 2,
          border: `2px solid ${theme.vars.palette.rule}`,
          backgroundImage: 'none',
          backgroundColor: theme.vars.palette.background.paper,
          color: theme.vars.palette.text.primary,
          boxShadow: 'none',
        }),
      },
    },
    MuiMenu: {
      styleOverrides: {
        paper: ({ theme }) => ({
          borderRadius: 2,
          border: `2px solid ${theme.vars.palette.rule}`,
          backgroundImage: 'none',
          backgroundColor: theme.vars.palette.background.paper,
          boxShadow: 'none',
        }),
      },
    },
    MuiMenuItem: { styleOverrides: { root: { minHeight: 48, fontFamily: SERIF, fontWeight: 600, fontSize: '1rem' } } },
    MuiRadio: { styleOverrides: { root: ({ theme }) => ({ color: theme.vars.palette.rule, padding: 10 }) } },
    MuiCheckbox: { styleOverrides: { root: ({ theme }) => ({ color: theme.vars.palette.rule, padding: 10 }) } },
    MuiFormControlLabel: {
      styleOverrides: {
        root: { marginLeft: 0, marginRight: 0, alignItems: 'flex-start' },
        label: { fontFamily: SERIF, fontSize: '1rem', lineHeight: 1.4, paddingTop: 9 },
      },
    },
    MuiSnackbarContent: {
      styleOverrides: {
        root: ({ theme }) => ({
          borderRadius: 2,
          fontFamily: SERIF,
          fontSize: '0.9375rem',
          backgroundColor: theme.vars.palette.text.primary,
          color: theme.vars.palette.background.default,
        }),
      },
    },
    MuiSkeleton: { defaultProps: { animation: 'pulse' } },
  },
});
