# Operator console design language

How the community's three web surfaces look, and where each decision lives in
code: the operator console (`/admin/*`), the member portal (`/members/*`) and
the default home page (`vtc-service/website-default/`). The console is the
densest of the three and most of this note is about it; the portal and the home
page share its tokens, type and colour theme.

This note describes what the code does. When the two disagree, the code is
right and this note is out of date.

## 1. Reference frame

An application UI, not a marketing site: a monochrome base, crisp 1px borders,
tight type, one brand colour used with restraint, dense tables that stay
readable. Both colour themes are first-class.

Not used: gradients on chrome (the community mark is the one exception, §3),
bouncy motion, glassmorphism, emoji as icons.

## 2. Where it lives

| What | File |
|---|---|
| Design tokens (source of truth) | `vtc-service/admin-ui/src/styles/tokens.css` |
| Home page's copy of the tokens | `vtc-service/website-default/tokens.css` — byte-identical; `src/website/default_site.rs` fails a test if the two drift |
| Console stylesheets | `admin-ui/src/styles/index.css` imports, in cascade order, `tokens.css`, `base.css`, `shell.css`, `components.css`, `pages.css`, then one file per built-in screen under `styles/plugins/` |
| Theme switcher styles | `admin-ui/src/styles/theme-switcher.css`, imported by `components/ThemeSwitcher.tsx` because the portal bundle draws it too |
| Community sign-in look (portal and console sign-in page) | `admin-ui/src/signin/signin.css`, scoped under `.vtc-signin` |
| Member portal's own styles | `admin-ui/src/members/members.css` |
| Home page | `website-default/site.css`, `fonts.css`, `theme.js` |

Rules read tokens, not raw values. A screen's stylesheet holds only layout
particular to that screen; anything two screens share moves to
`components.css`.

## 3. Tokens

### Type

IBM Plex Sans and IBM Plex Mono on every surface, self-hosted. The console and
the portal import them from `@fontsource/ibm-plex-sans` and
`@fontsource/ibm-plex-mono` (`main.tsx`, `members/main.tsx`); the home page
carries woff2 copies under `website-default/fonts/` (SIL OFL 1.1), declared in
`fonts.css`. No third-party font request is made. There is no separate display
face: `--font-display` is kept as a name and resolves to `--font-sans`.

```css
--font-sans: "IBM Plex Sans", ui-sans-serif, system-ui, …, sans-serif;
--font-mono: "IBM Plex Mono", ui-monospace, SFMono-Regular, …, monospace;
```

A 14px base, because the console is dense. The portal and the home page set
their own larger body size. Each step has a size and a leading token
(`--text-sm` / `--text-sm-leading`):

| Token | Size / leading | Typical use |
|---|---|---|
| `--text-xs` | 11 / 16px | Uppercase labels, chips, table headings |
| `--text-sm` | 12 / 18px | Secondary text, breadcrumbs |
| `--text-base` | 14 / 20px | Default UI text, table cells |
| `--text-md` | 15 / 22px | Empty-state titles, page counts |
| `--text-lg` | 17 / 24px | |
| `--text-xl` | 21 / 28px | Page titles |
| `--text-2xl` | 28 / 34px | Stat-tile figures |

Weights `--weight-regular` (400) to `--weight-bold` (700); headings use 600.
Tracking: `--tracking-tight` (-0.011em, body), `--tracking-tighter` (-0.02em,
headings), `--tracking-wide` (0.02em, uppercase labels), `--tracking-caps`
(0.08em). Every numeric surface (tables, stat tiles, timestamps) uses
`font-variant-numeric: tabular-nums` (`base.css`).

### Colour

- **Brand: indigo.** `--brand-50` to `--brand-700`, with `--brand-500`
  `#5b5bd6` as the light-theme brand and `--brand-400` `#7c7ce8` as the dark.
  `--accent-violet` and `--accent-pink` are for the community mark, the home
  page's hero wash and the relationships graph, not for chrome.
- **Brand roles.** Rules use the roles, not the ramp: `--brand`,
  `--brand-strong` (`--brand-hover`), `--brand-fg` (`--on-brand`),
  `--brand-soft`, `--brand-tint`, `--brand-tint-strong` and `--focus-ring`.
- **Community accent.** A community that sets an accent colour on the Branding
  card gets it as the console's brand. Once the viewer can sign,
  `lib/community-identity.ts` sets `--community-accent` and
  `--community-accent-fg` (white or near-black, whichever meets 4.5:1) on
  `<html>` with a `data-community-accent` attribute, and
  `:root[data-community-accent]` in `tokens.css` re-points `--brand`,
  `--brand-strong` and `--brand-fg`. In the dark theme the accent is mixed
  towards white so a dark accent stays legible. Nothing else changes; without
  an accent the indigo stands. The portal and the home page keep the indigo.
- **Greys.** `--gray-50` to `--gray-950`, cool and faintly indigo.
- **Surfaces.** `--bg`, `--bg-elev`, `--bg-subtle`, `--bg-hover`, `--border`,
  `--border-strong`, `--text`, `--text-muted`, `--text-faint`.
- **Semantic.** `--success`, `--warning`, `--danger`, each with a `-soft`
  background, plus `--danger-tint`. Used on state indicators only.
- **Verdicts.** `--vd-allow` (emerald), `--vd-deny` (rose), `--vd-refer`
  (amber), `--vd-more` (violet) for the four policy effects, on the Policies
  screen and anywhere else that renders a decision. They keep their values
  whatever the brand is.
- **Community mark.** `--mark-gradient` (brand to violet) is the mark shown
  when the community has no logo.

The home page's filled buttons stay on `--brand-500` with white text in both
themes, since white on the lighter dark-theme brand falls short of 4.5:1
(`site.css`).

### Spacing, sizes and radius

A 4px grid: `--space-1` (4px) to `--space-16` (64px). Controls are
`--control-h` 36px (`--control-h-sm` 28px); table rows are `--row-h` 40px.

| Token | Value | Use |
|---|---|---|
| `--radius-sm` | 4px | Focus outlines, tight controls |
| `--radius-md` | 8px | Buttons, inputs, nav items, toasts |
| `--radius-lg` | 12px | Cards, stat tiles |
| `--radius-xl` | 20px | Cards on the sign-in pages, the portal and the home page |
| `--radius-pill` | 999px | Chips, switches, the console pill |

### Elevation and motion

A 1px border is the primary affordance. `--elev-1` to `--elev-3` add a soft
shadow for floating surfaces (dropdowns, toasts, dialogs); cards carry no
shadow. `--shadow-card` and `--shadow-hover` are for the cards on the sign-in
pages, the portal and the home page.

Motion is expo-out, `cubic-bezier(0.16, 1, 0.3, 1)`: `--motion-fast` 120ms
(hover, focus), `--motion-medium` 180ms (toasts, dialogs), `--motion-slow`
260ms. Tables, page changes and content do not animate. The home page, the
sign-in look and the console's switch turn their transitions off under
`prefers-reduced-motion: reduce`.

## 4. Colour theme

`tokens.css` sets `color-scheme: light dark` and writes every surface colour as
`light-dark(…)`, so a page follows the operating system with no script.
`[data-theme="light"]` or `[data-theme="dark"]` on `<html>` pins one theme by
setting `color-scheme`, and the cascade follows.

One **Match system / Light / Dark** switcher, as an ARIA radio group, on every
surface:

- the console: in the account menu (`components/ThemeSwitcher.tsx`);
- the console's sign-in page and the member portal: at the end of the top bar
  (`signin/SignInLayout.tsx`);
- the home page: in the top bar, from `website-default/theme.js`, loaded in
  `<head>` without `defer` so a pinned theme applies before first paint, and
  hidden without JavaScript.

All three store the choice in `localStorage` under `vtc-admin-theme`
(`lib/theme.ts`, `THEME_STORAGE_KEY`), so one choice holds on the whole origin
and a `storage` event keeps open tabs in step. *Match system* stores nothing.

## 5. Icons

`lucide-react`, outlined, stroke width 1.75. 16px in the sidebar, buttons and
compact empty states; 20px in full empty states. A third-party plugin's SVG icon
is rendered as an `<img>` (`components/PluginIcon.tsx`), never as inline
markup.

## 6. The console shell

`App.tsx`, styled in `shell.css`.

- **Top bar** (52px): the community's mark (logo, or the gradient) and name
  from its public profile, an "Operator console" pill, **Jump to… ⌘K**, the
  live indicator (`components/LiveIndicator.tsx`) and the account menu.
- **Sidebar** (220px): grouped under **Overview** (Dashboard, Actions, Audit
  trail), **Membership** (Join requests, Members, Invitations, Vetting,
  Relationships), **Governance** (Policies, Roles, Access control, Sessions)
  and **Community** (Profile, Recognition, Data rooms, Repos), then **More**
  for plugins that name no group (`plugin-api.ts`, `NAV_GROUPS`;
  `lib/nav-groups.ts`). A group the viewer can see nothing in is hidden. The
  active entry sits on `--brand-soft` in `--brand-strong`. It collapses to a
  64px icon rail on a wide screen and becomes a slide-over at 720px and below.
  *Policies* is the ceremonies plugin and keeps its route, `/ceremonies`;
  *Profile* keeps `/profile`.
- **Account menu** (`components/AccountMenu.tsx`): My passkeys, Signing keys
  (plugins with `group: "account"`), the theme switcher and Sign out.
- **Attention strip** (`components/AttentionStrip.tsx`): one strip above the
  page instead of stacked banners, most severe item first. Critical items (an
  operator's offline write, a cooling-off against you, break-glass) and
  single-administrator mode are always shown and cannot be dismissed; the rest
  fold behind "Show N more". The signing-key renewal reminder and the
  actions-waiting notice live here too; the latter can be dismissed for the
  session.
- **Command palette** (`components/CommandPalette.tsx`, `lib/commands.ts`):
  ⌘K / Ctrl+K lists every screen the viewer can see and a short list of
  actions. Built without a dependency.

The page area scrolls, not the window, so the top bar and sidebar stay put and
a table's sticky header sticks under the bar. The console uses the full width;
running prose keeps a readable measure through `.prose-measure`.

## 7. Shared components

Every built-in screen is built from these (`admin-ui/src/components/`):

| Component | What it is |
|---|---|
| `PageHeader` | Breadcrumb (group / page, from the plugin being rendered), the title as the page's `<h2>` with an optional count beside it, a primary-action slot and an optional lead. Sub-pages pass a `trail`. |
| `Tabs`, `TabLinks` | One tab component in two looks: `underline` (with counts) and `segmented` (view toggles). Buttons form an ARIA tablist with roving focus and arrow, Home and End keys; `TabLinks` are tabs that are routes. |
| `DataTable`, `useSortedRows` | The `data-table` head with `SortableHeader` built in for any column with a `sortKey`, and a header that stays in view. Lists read whole sort on click and keep their given order until then; server-paged lists do not sort. |
| `Field` | A labelled control in two shapes: wrapping, or pointing (`htmlFor`). A hint or error sits under the control, never inside the label. |
| `EmptyState` | Icon, title, reason and action; or `compact`, one muted line inside a card. |
| `Switch` | A native checkbox with `role="switch"` under a drawn track, for one setting that is on or off. Multi-select lists stay checkboxes. |
| `ConfirmDialog`, `TypedConfirmDialog` | Modal confirmation, the second asking the operator to type a value. |
| `ThemeSwitcher` | §4. |
| `InfoTip`, `CopyButton`, `DidText`, `NamedDid`, `DidQrButton` | An explanation on hover or focus; copy; a DID abbreviated at its colons with the whole on hover; a DID shown by its name with the identifier beside it; a DID's QR code. |

Element-level conventions (`components.css`):

- **Buttons**: 36px, 32px (`.sm`), 40px (`.lg`). Primary is solid `--brand`;
  secondary is transparent with a 1px border; destructive is transparent with
  a red-tinted border, solid red on hover; `button.link` is a text link.
- **Focus**: a 2px `--focus-ring` outline, outside the element by 2px; inputs
  draw it 1px inside their border; a primary button gets a gap so the ring
  stays visible on the brand fill (`base.css`).
- **Cards**: `--bg-elev`, 1px border, `--radius-lg`, no shadow. Card headings
  are small uppercase labels.
- **Tables**: 40px rows, uppercase `--text-xs` headings, a hover tint,
  monospace for DIDs and identifiers.
- **Chips**: pills, monochrome by default; a state chip colours its text and
  border, not its background.
- **Toasts**: bottom right, a 4px left border in the state colour.
- **Colour is never the only signal.** Every dot, chip and rail has a word or
  an ARIA equivalent beside it, and single-administrator mode is drawn with a
  dashed border and hatching as well as colour.

## 8. Screen patterns

- **List screens** (Members, Access control): the page header with the count
  and the primary action, a toolbar of filters on the page (`.list-toolbar`),
  then the table in a card that runs to its edges (`.table-card`).
- **Dashboard**: "what needs me", then health. A greeting with **Invite a
  member** for a viewer who may, a row of stat tiles (a tile needing attention
  carries a warning rail), then **Waiting for you** beside **Service health**,
  one column below 64rem.
- **Actions**: an inbox. Each row has a chip row, the verified summary, one
  meta line (who asked, when, the match code) and the facts; the decision
  buttons sit in a column on the right, under the facts on a narrow screen.
- **Policies**: a standard page like the others; verdicts use the `--vd-*`
  colours.

What each screen shows is described in
[`website-and-admin.md`](../03-vtc/website-and-admin.md).

## 9. Changing it

- Edit `admin-ui/src/styles/tokens.css`, then copy it over
  `website-default/tokens.css`; the drift test will fail otherwise.
- A new screen's layout goes in its own `styles/plugins/<screen>.css`,
  imported from `index.css` after the shared files.
- An operator restyles the console without rebuilding by serving it from a
  directory (`admin_ui.mode = "directory"`, `website-and-admin.md`). That copy
  is a snapshot of the console it was exported from: it keeps its look until
  the operator exports again.

## 10. Out of scope

- Not a CSS framework. The stylesheets are hand-written against the tokens.
- No component library: dialogs, menus, tabs, the palette and the switch are
  built in-tree.
- The brand colour is the only brand decision, and a community may replace it
  with its own accent.
