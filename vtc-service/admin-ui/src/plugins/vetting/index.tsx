// Vetting plugin — naming vetters, what applicants see, automatic grants,
// withdrawn statements and the published requirements.
//
// Two more pieces live beside the surfaces they belong to: a join request's
// vetting facts on its detail page (`JoinRequestVetting.tsx`), and community
// branding on the Community profile page (`BrandingCard.tsx`).
//
// Section links are absolute: the shell mounts plugins on `path/*`, where a
// relative link outside the descendant `<Routes>` would resolve against the
// current section rather than the plugin root.

import { NavLink, Route, Routes } from "react-router-dom";

import { AutoGrantPanel } from "./AutoGrantPanel";
import { RegistryPreview } from "./RegistryPreview";
import { RequirementsPanel } from "./RequirementsPanel";
import { VETTING_PATH } from "./ui";
import { VettersPanel } from "./VettersPanel";
import { WithdrawalsPanel } from "./WithdrawalsPanel";

const SECTIONS = [
  { path: "", label: "Vetters" },
  { path: "/registry", label: "Registry preview" },
  { path: "/auto-grant", label: "Automatic grants" },
  { path: "/withdrawals", label: "Withdrawals" },
  { path: "/requirements", label: "Requirements" },
] as const;

export function Vetting() {
  return (
    <section className="page">
      <h2>Vetting</h2>
      <p className="lead">
        Choose which members vet applicants, check what applicants see when they
        look for a vetter, and follow up when a vetter withdraws a statement.
      </p>

      <nav className="subnav" aria-label="Vetting sections">
        {SECTIONS.map((section) => (
          <NavLink
            key={section.label}
            to={`${VETTING_PATH}${section.path}`}
            end={section.path === ""}
          >
            {section.label}
          </NavLink>
        ))}
      </nav>

      <Routes>
        <Route index element={<VettersPanel />} />
        <Route path="registry" element={<RegistryPreview />} />
        <Route path="auto-grant" element={<AutoGrantPanel />} />
        <Route path="withdrawals" element={<WithdrawalsPanel />} />
        <Route path="requirements" element={<RequirementsPanel />} />
        <Route
          path="*"
          element={
            <p className="muted">
              There is no such vetting section. Choose one of the sections above.
            </p>
          }
        />
      </Routes>
    </section>
  );
}
