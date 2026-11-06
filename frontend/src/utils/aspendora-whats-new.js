// Aspendora fork: helpers for the What's New page (src/pages/cipp/whats-new.jsx).
import whatsNew from "../data/aspendora-whats-new.json";

export const WHATS_NEW_SEEN_KEY = "aspendora_whats_new_seen";

export const latestWhatsNewDate = () =>
  whatsNew.entries.reduce((max, e) => (e.date > max ? e.date : max), "");

// True when an entry is newer than the date the operator last opened the page.
export const hasUnseenWhatsNew = () => {
  if (typeof window === "undefined") return false;
  const seen = window.localStorage.getItem(WHATS_NEW_SEEN_KEY);
  return !seen || latestWhatsNewDate() > seen;
};
