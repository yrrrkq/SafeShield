/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#070b14",
          card: "#0d1527",
          cardBorder: "#1e293b",
          cyan: "#00f0ff",
          emerald: "#00ff9d",
          red: "#ff0055",
          amber: "#ffb703",
          blue: "#3b82f6",
          darker: "#030712"
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Consolas', 'Menlo', 'monospace'],
        sans: ['"Inter"', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-glow': 'pulseGlow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 6s linear infinite',
        'flash-broadcast': 'flashBroadcast 1.5s ease-out',
      },
      keyframes: {
        pulseGlow: {
          '0%, 100%': { opacity: '1', filter: 'drop-shadow(0 0 12px rgba(0, 240, 255, 0.6))' },
          '50%': { opacity: '0.6', filter: 'drop-shadow(0 0 4px rgba(0, 240, 255, 0.2))' },
        },
        flashBroadcast: {
          '0%': { opacity: '0', transform: 'scale(0.95)' },
          '20%': { opacity: '1', transform: 'scale(1.02)' },
          '80%': { opacity: '1', transform: 'scale(1)' },
          '100%': { opacity: '0', transform: 'scale(0.98)' }
        }
      }
    },
  },
  plugins: [],
}
