export const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";
export const WS_URL = import.meta.env.VITE_WS_URL ?? (() => {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/ws`;
})();
