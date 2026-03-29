import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        shield: {
          bg: "#0a0e1a",
          surface: "#111827",
          border: "#1f2937",
          accent: "#06b6d4",
          danger: "#ef4444",
          warn: "#f59e0b",
          info: "#3b82f6",
          muted: "#6b7280",
          text: "#f9fafb",
          subtext: "#9ca3af",
        },
      },
    },
  },
  plugins: [],
} satisfies Config;