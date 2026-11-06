// What's New (Aspendora fork): features our fork adds on top of upstream CIPP.
// Content lives in src/data/aspendora-whats-new.json; see docs/aspendora-whats-new.md for how to add entries.
import { useEffect, useMemo, useState } from "react";
import NextLink from "next/link";
import {
  Box,
  Card,
  CardContent,
  Chip,
  Container,
  InputAdornment,
  Link,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { Layout as DashboardLayout } from "../../layouts/index";
import { CippIcons } from "../../utils/icon-registry";
import whatsNew from "../../data/aspendora-whats-new.json";
import { WHATS_NEW_SEEN_KEY, latestWhatsNewDate } from "../../utils/aspendora-whats-new";

const monthLabel = (date) =>
  new Date(`${date}T12:00:00`).toLocaleDateString(undefined, { year: "numeric", month: "long" });

const dayLabel = (date) =>
  new Date(`${date}T12:00:00`).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });

const Page = () => {
  const [search, setSearch] = useState("");
  const [area, setArea] = useState(null);
  // The date the operator last opened this page, read once so "New" badges survive this visit.
  const [lastSeen, setLastSeen] = useState(undefined);

  useEffect(() => {
    if (typeof window === "undefined") return;
    setLastSeen(window.localStorage.getItem(WHATS_NEW_SEEN_KEY));
    window.localStorage.setItem(WHATS_NEW_SEEN_KEY, latestWhatsNewDate());
    window.dispatchEvent(new Event("aspendora-whats-new-seen"));
  }, []);

  const entries = useMemo(() => {
    const term = search.trim().toLowerCase();
    return [...whatsNew.entries]
      .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0))
      .filter((e) => !area || e.area === area)
      .filter(
        (e) =>
          !term ||
          [e.title, e.summary, e.area, e.ref, e.path].some((v) =>
            String(v ?? "").toLowerCase().includes(term)
          )
      );
  }, [search, area]);

  const groups = useMemo(() => {
    const out = [];
    for (const e of entries) {
      const key = e.date.slice(0, 7);
      if (!out.length || out[out.length - 1].key !== key) out.push({ key, label: monthLabel(e.date), items: [] });
      out[out.length - 1].items.push(e);
    }
    return out;
  }, [entries]);

  const isNew = (e) => lastSeen !== undefined && (lastSeen === null || e.date > lastSeen);

  return (
    <Container maxWidth="lg" sx={{ py: 3 }}>
      <Stack spacing={3}>
        <Box>
          <Typography variant="h4">What&apos;s New (Aspendora)</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Features our CIPP adds on top of upstream CyberDrain CIPP, newest first. Upstream changes are
            under <em>View release notes</em> in the account menu.
          </Typography>
        </Box>

        <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }}>
          <TextField
            size="small"
            placeholder="Search features"
            value={search}
            onChange={(ev) => setSearch(ev.target.value)}
            sx={{ minWidth: 260 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <CippIcons.MagnifyingGlassIcon fontSize="small" />
                </InputAdornment>
              ),
            }}
          />
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
            <Chip label="All" color={area ? "default" : "primary"} onClick={() => setArea(null)} />
            {whatsNew.areas.map((a) => (
              <Chip
                key={a}
                label={a}
                color={area === a ? "primary" : "default"}
                onClick={() => setArea(area === a ? null : a)}
              />
            ))}
          </Stack>
        </Stack>

        {groups.length === 0 && (
          <Typography color="text.secondary">No features match.</Typography>
        )}

        {groups.map((g) => (
          <Stack key={g.key} spacing={1.5}>
            <Typography variant="overline" color="text.secondary">
              {g.label}
            </Typography>
            {g.items.map((e) => (
              <Card key={e.id} variant="outlined">
                <CardContent>
                  <Stack direction="row" spacing={1} alignItems="center" useFlexGap flexWrap="wrap">
                    <Typography variant="h6" component="h2">
                      {e.title}
                    </Typography>
                    {isNew(e) && <Chip size="small" color="success" label="New" />}
                  </Stack>
                  <Stack direction="row" spacing={1} sx={{ mt: 0.5 }} useFlexGap flexWrap="wrap">
                    <Chip size="small" variant="outlined" label={e.area} />
                    <Typography variant="caption" color="text.secondary" sx={{ alignSelf: "center" }}>
                      {dayLabel(e.date)}
                      {e.ref ? ` · ${e.ref}` : ""}
                    </Typography>
                  </Stack>
                  <Typography variant="body2" sx={{ mt: 1.5 }}>
                    {e.summary}
                  </Typography>
                  {e.path && (
                    <Link component={NextLink} href={e.path} variant="body2" sx={{ mt: 1, display: "inline-block" }}>
                      Open {e.path}
                    </Link>
                  )}
                </CardContent>
              </Card>
            ))}
          </Stack>
        ))}
      </Stack>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
