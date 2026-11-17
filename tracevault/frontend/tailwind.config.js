/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: { DEFAULT: '#101318', 2: '#151A21' },
        panel: { DEFAULT: '#1A2029', 2: '#202733', 3: '#262E3B' },
        line: { DEFAULT: '#303A47', soft: '#252D38' },
        accent: { DEFAULT: '#67C8D8', dim: '#3F7F8A' },
        secondary: '#8C9CFF',
        suspicious: '#E6AA55',
        critical: '#E56B72',
        verified: '#70B99B',
        muted: '#929EAC',
        ink: { DEFAULT: '#D7DEE6', bright: '#EEF2F6' },
        relation: '#B08CFF',
        src: {
          evtx: '#6FA8DC',
          registry: '#C89B6D',
          prefetch: '#7FC6A4',
          amcache: '#A3B86C',
          browser: '#D58FB8',
          filesystem: '#9AA7B8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', '14px'],
        xs: ['11px', '16px'],
        sm: ['12.5px', '18px'],
      },
    },
  },
  plugins: [],
};
