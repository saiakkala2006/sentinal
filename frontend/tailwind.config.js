/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: '#F5F2EC',           // warm cream background
          card: '#FDFCF8',         // off-white card surface
          cardBorder: '#DDD8CE',   // warm stone border
          green: '#4A7C59',        // sage/forest green — primary accent
          mint: '#7EBC8A',         // light mint green — secondary
          sage: '#A8C5A0',         // soft sage — tertiary
          cream: '#F0EBE1',        // warm cream
          sand: '#E8E0D0',         // sandy off-white
          stone: '#8D8378',        // warm stone muted
          amber: '#C49A3C',        // muted warm amber (alerts)
          rose: '#B85C6A',         // muted dusty rose (danger)
          sky: '#5B8DB8',          // soft calm blue
          muted: '#7A7368',        // warm muted text
        }
      },
      backgroundImage: {
        'leaf-grid': 'radial-gradient(circle, rgba(74, 124, 89, 0.06) 1px, transparent 1px)',
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      animation: {
        'pulse-soft': 'pulse-soft 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float': 'float 6s ease-in-out infinite',
        'fade-in': 'fade-in 0.4s ease-out',
      },
      keyframes: {
        'pulse-soft': {
          '0%, 100%': { opacity: '1', filter: 'drop-shadow(0 0 8px rgba(74, 124, 89, 0.4))' },
          '50%': { opacity: '0.7', filter: 'drop-shadow(0 0 3px rgba(74, 124, 89, 0.15))' },
        },
        'float': {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-6px)' },
        },
        'fade-in': {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      }
    },
  },
  plugins: [],
};
