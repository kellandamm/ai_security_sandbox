/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        "soc-bg": "#f8fafc",
        "soc-panel": "#ffffff",
        "soc-border": "#d7e0ea",
        "soc-accent": "#edf4ff",
        "soc-blue": "#1d4ed8",
        "soc-cyan": "#0891b2",
        "soc-green": "#15803d",
        "soc-red": "#b91c1c",
        "soc-orange": "#c2410c",
        "soc-yellow": "#a16207",
        "soc-text": "#0f172a",
        "soc-muted": "#475569",
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Consolas", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "fade-in": "fadeIn 0.3s ease-in-out",
        "slide-in": "slideIn 0.3s ease-out",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideIn: {
          "0%": { transform: "translateY(-4px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
      },
    },
  },
  plugins: [],
};
