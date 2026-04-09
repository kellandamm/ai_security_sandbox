/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        "soc-bg": "#0a0e1a",
        "soc-panel": "#0f1629",
        "soc-border": "#1e2d4a",
        "soc-accent": "#1a3a6b",
        "soc-blue": "#3b82f6",
        "soc-cyan": "#06b6d4",
        "soc-green": "#10b981",
        "soc-red": "#ef4444",
        "soc-orange": "#f59e0b",
        "soc-yellow": "#eab308",
        "soc-text": "#e2e8f0",
        "soc-muted": "#64748b",
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
