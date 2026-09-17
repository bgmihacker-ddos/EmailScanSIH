/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        /* Depth layers — the SOC "deck" */
        deck: '#0A0D13',
        surface: '#0F131B',
        raised: '#151A25',
        sunken: '#07090E',
        /* Structure */
        ink: '#E9EDF4',          /* primary text */
        'ink-dim': '#A6B0C2',    /* secondary text */
        'ink-mute': '#6B7689',   /* muted labels */
        'ink-faint': '#454F60',  /* disabled / subtle */
        hairline: 'rgba(255,255,255,0.06)',
        'hairline-strong': 'rgba(255,255,255,0.12)',
        /* Single interactive accent */
        accent: '#4C9EEB',
        'accent-soft': 'rgba(76,158,235,0.14)',
        /* Severity language — status only, never decoration */
        critical: '#F4586B',
        high: '#F0794A',
        medium: '#E8B44A',
        low: '#4C9EEB',
        safe: '#3ECF8E',
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', '"Fira Code"', 'monospace'],
      },
    },
  },
  plugins: [],
}
