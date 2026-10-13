// Icon set: 24px grid, 1.8 stroke, round joins — drawn to sit with Saira/Barlow.
const P = {
  vault: <><rect x="3.5" y="4" width="17" height="16" rx="3" /><circle cx="12" cy="12" r="3.4" /><path d="M12 8.6V7M12 17v-1.6M15.4 12H17M7 12h1.6M7 20v1.2M17 20v1.2" /></>,
  activity: <path d="M3 12h3.5l2.5-6 4 13 2.6-7H21" />,
  shield: <><path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6L12 3Z" /><path d="m9 12 2.2 2.2L15.5 10" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  camera: <><path d="M4 8.5A2.5 2.5 0 0 1 6.5 6H8l1.4-2h5.2L16 6h1.5A2.5 2.5 0 0 1 20 8.5v8A2.5 2.5 0 0 1 17.5 19h-11A2.5 2.5 0 0 1 4 16.5v-8Z" /><circle cx="12" cy="12.5" r="3.5" /></>,
  file: <><path d="M14 3H7.5A2.5 2.5 0 0 0 5 5.5v13A2.5 2.5 0 0 0 7.5 21h9a2.5 2.5 0 0 0 2.5-2.5V8l-5-5Z" /><path d="M14 3v5h5" /></>,
  image: <><rect x="3.5" y="4.5" width="17" height="15" rx="2.5" /><circle cx="9" cy="10" r="1.7" /><path d="m20 16-4.5-4.5L7 20" /></>,
  text: <><path d="M14 3H7.5A2.5 2.5 0 0 0 5 5.5v13A2.5 2.5 0 0 0 7.5 21h9a2.5 2.5 0 0 0 2.5-2.5V8l-5-5Z" /><path d="M8.5 12.5h7M8.5 16h5" /></>,
  pdf: <><path d="M14 3H7.5A2.5 2.5 0 0 0 5 5.5v13A2.5 2.5 0 0 0 7.5 21h9a2.5 2.5 0 0 0 2.5-2.5V8l-5-5Z" /><path d="M8.5 16.5v-4h1.3a1.3 1.3 0 0 1 0 2.6H8.5M13 16.5v-4h1.1a2 2 0 0 1 0 4H13Z" /></>,
  lock: <><rect x="5" y="10.5" width="14" height="10" rx="2.5" /><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" /><path d="M12 14.5v2" /></>,
  unlock: <><rect x="5" y="10.5" width="14" height="10" rx="2.5" /><path d="M8 10.5V8a4 4 0 0 1 7.6-1.7" /></>,
  trash: <><path d="M4.5 7h15M9.5 7V5h5v2M6.5 7l1 12.5a1.5 1.5 0 0 0 1.5 1.5h6a1.5 1.5 0 0 0 1.5-1.5L17.5 7" /><path d="M10 11v6M14 11v6" /></>,
  eye: <><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" /><circle cx="12" cy="12" r="3" /></>,
  download: <><path d="M12 4v11M7.5 11 12 15.5 16.5 11" /><path d="M5 19.5h14" /></>,
  pencil: <><path d="M14.5 5.5 18.5 9.5 9 19H5v-4l9.5-9.5Z" /><path d="m13 7 4 4" /></>,
  chevron: <path d="m9.5 6 6 6-6 6" />,
  back: <path d="m14.5 6-6 6 6 6" />,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  x: <path d="M6.5 6.5 17.5 17.5M17.5 6.5 6.5 17.5" />,
  info: <><circle cx="12" cy="12" r="8.5" /><path d="M12 11v5.5M12 7.8v.2" /></>,
  key: <><circle cx="8" cy="15.5" r="4" /><path d="m11 12.5 8.5-8.5M16 7l2.5 2.5M14 9l2 2" /></>,
  fingerprint: <><path d="M6.6 17.6c.9-1.8 1.4-3.7 1.4-5.6a4 4 0 0 1 8 0c0 2.8-.6 5.6-1.6 8" /><path d="M12 12c0 3-.7 6-2 8.6M4.6 14.8A11 11 0 0 0 5 12a7 7 0 0 1 12.2-4.7M18.8 10.2c.3 1.6.2 3.4-.1 5.2" /></>,
  server: <><rect x="4" y="4" width="16" height="7" rx="2" /><rect x="4" y="13" width="16" height="7" rx="2" /><path d="M8 7.5h.01M8 16.5h.01M12 7.5h4M12 16.5h4" /></>,
  idcard: <><rect x="3" y="5" width="18" height="14" rx="2.5" /><circle cx="9" cy="11" r="2.2" /><path d="M5.8 16c.6-1.4 1.8-2.2 3.2-2.2s2.6.8 3.2 2.2M14.5 10h3.5M14.5 13.5h3.5" /></>,
  health: <path d="M12 20s-7.5-4.5-7.5-10A4.3 4.3 0 0 1 12 7.6 4.3 4.3 0 0 1 19.5 10c0 5.5-7.5 10-7.5 10Z" />,
  money: <><rect x="3" y="6" width="18" height="12" rx="2.5" /><circle cx="12" cy="12" r="2.6" /><path d="M6.5 9.5v.01M17.5 14.5v.01" /></>,
  home: <><path d="M4 11 12 4.5 20 11" /><path d="M6 9.5V19a1 1 0 0 0 1 1h3.5v-5h3v5H17a1 1 0 0 0 1-1V9.5" /></>,
  user: <><circle cx="12" cy="8.5" r="3.8" /><path d="M4.8 20c1.2-3.6 4-5.4 7.2-5.4s6 1.8 7.2 5.4" /></>,
  folder: <path d="M3.5 7.5A2 2 0 0 1 5.5 5.5h4l2 2.2h7a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2V7.5Z" />,
  search: <><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4.5 4.5" /></>,
  alert: <><path d="M12 4 2.8 19.5h18.4L12 4Z" /><path d="M12 10v4.5M12 17v.01" /></>,
  chain: <><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.2 1.2" /><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.2-1.2" /></>,
  clock: <><circle cx="12" cy="12" r="8.5" /><path d="M12 7.5V12l3 2" /></>,
  out: <><path d="M14 4.5h3.5a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H14" /><path d="M10 8 6 12l4 4M6 12h9" /></>,
  sparkle: <path d="M12 3.5 13.9 10 20.5 12 13.9 14 12 20.5 10.1 14 3.5 12 10.1 10 12 3.5Z" />,
  signal: <><path d="M5 18.5a10 10 0 0 1 14 0M8 15.5a6 6 0 0 1 8 0" /><circle cx="12" cy="18.5" r="1" /></>,
  qr: <><rect x="4" y="4" width="6" height="6" rx="1" /><rect x="14" y="4" width="6" height="6" rx="1" /><rect x="4" y="14" width="6" height="6" rx="1" /><path d="M14 14h2.5v2.5H14zM18 18h2M20 14v2M14 20h2" /></>,
  scan: <><path d="M4 8V6a2 2 0 0 1 2-2h2M16 4h2a2 2 0 0 1 2 2v2M20 16v2a2 2 0 0 1-2 2h-2M8 20H6a2 2 0 0 1-2-2v-2" /><path d="M7 12h10" /></>,
  users: <><circle cx="9" cy="9" r="3.2" /><path d="M3.5 19c.9-3 3-4.5 5.5-4.5s4.6 1.5 5.5 4.5" /><circle cx="16.5" cy="8" r="2.6" /><path d="M15.5 13.2c2.3-.3 4.2 1 5 3.6" /></>,
  passport: <><rect x="5" y="3" width="14" height="18" rx="2" /><circle cx="12" cy="10" r="3.2" /><path d="M8.8 10h6.4M12 6.8c-1 .9-1.5 2-1.5 3.2s.5 2.3 1.5 3.2c1-.9 1.5-2 1.5-3.2s-.5-2.3-1.5-3.2ZM9 17h6" /></>,
  station: <><path d="M4 20h16M6 20V9l6-4 6 4v11" /><path d="M10 20v-5h4v5M9.5 11h5" /></>,
  siren: <><path d="M7 17v-5a5 5 0 0 1 10 0v5" /><path d="M5 17h14v3H5zM12 3v1.5M4.2 6.2l1 1M19.8 6.2l-1 1" /></>,
  globe: <><circle cx="12" cy="12" r="8.5" /><path d="M3.5 12h17M12 3.5c2.3 2.4 3.4 5.2 3.4 8.5s-1.1 6.1-3.4 8.5c-2.3-2.4-3.4-5.2-3.4-8.5S9.7 5.9 12 3.5Z" /></>,
  wifi_off: <><path d="M4 4.5 20 19.5M8.5 15.5a5.5 5.5 0 0 1 6.3-.8M5 12.3a10 10 0 0 1 3.2-2M19 12.3a10 10 0 0 0-6.3-2.7" /><circle cx="12" cy="18.5" r="1" /></>,
};

export function Icon({ name, label }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"
      role={label ? "img" : undefined} aria-label={label} aria-hidden={label ? undefined : "true"}>
      {P[name] || P.file}
    </svg>
  );
}

export const CATEGORIES = [
  { id: "identity", label: "Identity", icon: "idcard" },
  { id: "health", label: "Health", icon: "health" },
  { id: "money", label: "Money", icon: "money" },
  { id: "home", label: "Home", icon: "home" },
  { id: "personal", label: "Personal", icon: "user" },
  { id: "other", label: "Other", icon: "folder" },
];
export const categoryOf = (id) => CATEGORIES.find((c) => c.id === id) || CATEGORIES[5];

export function kindIcon(type = "") {
  if (type.startsWith("image/")) return "image";
  if (type === "application/pdf") return "pdf";
  if (type.startsWith("text/") || type === "application/json") return "text";
  return "file";
}
