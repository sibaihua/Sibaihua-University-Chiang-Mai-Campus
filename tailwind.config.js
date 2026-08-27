/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html"],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#1E3A5F',
          dark: '#142740',
          light: '#2B4E7D',
          subtle: '#5A7394',
          bgLight: '#f8fafc'
        }
      }
    }
  },
  plugins: []
};
