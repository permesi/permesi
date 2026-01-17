/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.rs"],
  safelist: [
    "hidden",
    "opacity-70",
    "cursor-not-allowed",
    "border-b-2",
    "border-[#0000002d]",
    "max-w-[38rem]",
    "text-base",
    "text-neutral-600",
    "text-neutral-50",
    "dark:text-neutral-50",
    "text-black",
  ],
  theme: {
    extend: {
      fontFamily: {
        "space-mono": ['"Space Mono"', "monospace"],
      },
    },
  },
  plugins: [],
};
