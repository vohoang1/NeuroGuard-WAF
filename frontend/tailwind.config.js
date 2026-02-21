/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                soc: {
                    900: '#0F172A', // Deep space dark blue (background)
                    800: '#1E293B', // Slightly lighter for cards/panels
                    700: '#334155', // Borders
                    accent: '#38BDF8', // Cyan blue for highlights/active
                    success: '#10B981', // Emerald green
                    warn: '#F59E0B',    // Amber
                    danger: '#EF4444',   // Red
                }
            },
            fontFamily: {
                sans: ['Inter', 'Roboto', 'sans-serif'],
                mono: ['Fira Code', 'Courier New', 'monospace'],
            }
        },
    },
    plugins: [],
}
