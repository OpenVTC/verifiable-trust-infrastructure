// The shared components every screen is built from: PageHeader, Tabs,
// DataTable (+ useSortedRows), Field and EmptyState.

import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { Inbox } from "lucide-react";

import { DataTable, useSortedRows } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import { TabLinks, Tabs } from "@/components/Tabs";
import { PluginContext } from "@/lib/plugin-context";
import type { PluginManifest } from "@/plugin-api";

const MEMBERS: PluginManifest = {
  id: "members",
  label: "Members",
  path: "/members",
  group: "membership",
  reactComponent: () => null,
};

function inPlugin(ui: React.ReactNode, plugin: PluginManifest | null = MEMBERS) {
  return render(
    <MemoryRouter>
      <PluginContext.Provider value={plugin}>{ui}</PluginContext.Provider>
    </MemoryRouter>,
  );
}

describe("PageHeader", () => {
  it("places the page in its group, titles it from the plugin, and shows a count", () => {
    inPlugin(<PageHeader count={248} countLabel="248 members" actions={<button>Invite</button>} />);
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(crumbs).getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "Membership",
      "Members",
    ]);
    expect(within(crumbs).getByText("Members").getAttribute("aria-current")).toBe("page");
    // The count sits beside the heading, not in its name.
    expect(screen.getByRole("heading", { level: 2, name: "Members" })).toBeTruthy();
    expect(screen.getByLabelText("248 members").textContent).toBe("248");
    expect(screen.getByRole("button", { name: "Invite" })).toBeTruthy();
  });

  it("links back to the plugin from a sub-page", () => {
    inPlugin(<PageHeader title="Aroha K." trail={[{ label: "Aroha K." }]} />);
    const crumbs = screen.getByRole("navigation", { name: "Breadcrumb" });
    expect(within(crumbs).getByRole("link", { name: "Members" }).getAttribute("href")).toBe(
      "/members",
    );
    expect(screen.getByRole("heading", { level: 2, name: "Aroha K." })).toBeTruthy();
  });

  it("puts a plugin with no group under More", () => {
    inPlugin(<PageHeader />, { ...MEMBERS, group: undefined, label: "Old tool" });
    expect(screen.getByRole("navigation", { name: "Breadcrumb" }).textContent).toContain("More");
  });

  it("renders without a plugin, with no breadcrumb unless given one", () => {
    inPlugin(<PageHeader title="Step-up" lead="Confirm with your passkey." />, null);
    expect(screen.queryByRole("navigation", { name: "Breadcrumb" })).toBeNull();
    expect(screen.getByText("Confirm with your passkey.")).toBeTruthy();
  });
});

describe("Tabs", () => {
  function Harness() {
    const [v, setV] = useState<"a" | "b" | "c">("a");
    return (
      <Tabs
        label="Lists"
        value={v}
        onChange={setV}
        items={[
          { id: "a", label: "Waiting for me", count: 2, countLabel: "2 open" },
          { id: "b", label: "Requested by me", count: 0 },
          { id: "c", label: "History" },
        ]}
      />
    );
  }

  it("is a tablist with one selected tab in the Tab order and counts", () => {
    render(<Harness />);
    const list = screen.getByRole("tablist", { name: "Lists" });
    const tabs = within(list).getAllByRole("tab");
    expect(tabs.map((t) => t.getAttribute("aria-selected"))).toEqual(["true", "false", "false"]);
    expect(tabs.map((t) => t.tabIndex)).toEqual([0, -1, -1]);
    expect(within(tabs[0]!).getByLabelText("2 open").textContent).toBe("2");
    // A zero count is not shown.
    expect(tabs[1]!.textContent).toBe("Requested by me");
  });

  it("selects on click and moves with the arrow keys, Home and End", () => {
    render(<Harness />);
    const tab = (name: RegExp) => screen.getByRole("tab", { name });
    fireEvent.click(tab(/History/));
    expect(tab(/History/).getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(tab(/History/), { key: "ArrowRight" });
    expect(tab(/Waiting/).getAttribute("aria-selected")).toBe("true");
    expect(document.activeElement).toBe(tab(/Waiting/));
    fireEvent.keyDown(tab(/Waiting/), { key: "ArrowLeft" });
    expect(tab(/History/).getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(tab(/History/), { key: "Home" });
    expect(tab(/Waiting/).getAttribute("aria-selected")).toBe("true");
    fireEvent.keyDown(tab(/Waiting/), { key: "End" });
    expect(tab(/History/).getAttribute("aria-selected")).toBe("true");
  });

  it("has a segmented look for view toggles", () => {
    const { container } = render(
      <Tabs
        variant="segmented"
        value="flow"
        onChange={() => undefined}
        items={[
          { id: "english", label: "Plain English" },
          { id: "flow", label: "Flow" },
        ]}
      />,
    );
    expect(container.querySelector(".tabs--segmented")).toBeTruthy();
    expect(screen.getByRole("tab", { name: "Flow" }).getAttribute("aria-selected")).toBe("true");
  });

  it("renders route tabs as links with the current one marked", () => {
    render(
      <MemoryRouter initialEntries={["/vetting/registry"]}>
        <TabLinks
          label="Vetting sections"
          items={[
            { id: "vetters", label: "Vetters", to: "/vetting", end: true },
            { id: "registry", label: "Registry", to: "/vetting/registry" },
          ]}
        />
      </MemoryRouter>,
    );
    const nav = screen.getByRole("navigation", { name: "Vetting sections" });
    expect(within(nav).getByRole("link", { name: "Registry" }).getAttribute("aria-current")).toBe(
      "page",
    );
    expect(within(nav).getByRole("link", { name: "Vetters" }).getAttribute("aria-current")).toBeNull();
  });
});

describe("DataTable", () => {
  type Row = { name: string; joined: string | null };
  const ROWS: Row[] = [
    { name: "Lee", joined: "2026-04-02" },
    { name: "Aroha", joined: "2026-03-12" },
    { name: "Tama", joined: null },
  ];
  function Harness() {
    const { rows, sort, onSort } = useSortedRows<Row, "name" | "joined">(
      ROWS,
      (r, k) => (k === "name" ? r.name : r.joined),
      { initialDir: { joined: "desc" } },
    );
    return (
      <DataTable
        caption="Members"
        sort={sort}
        onSort={onSort}
        columns={[
          { key: "name", label: "Name", sortKey: "name" },
          { key: "joined", label: "Joined", sortKey: "joined", tip: "When they joined" },
          { key: "note", label: "Note" },
        ]}
      >
        {rows.map((r) => (
          <tr key={r.name}>
            <td>{r.name}</td>
            <td>{r.joined ?? ""}</td>
            <td />
          </tr>
        ))}
      </DataTable>
    );
  }
  const names = () =>
    screen
      .getAllByRole("row")
      .slice(1)
      .map((r) => r.querySelector("td")!.textContent);

  it("keeps the given order until a header is clicked, then sorts and flips", () => {
    render(<Harness />);
    expect(names()).toEqual(["Lee", "Aroha", "Tama"]);
    const nameHeader = screen.getByRole("columnheader", { name: /Name/ });
    expect(nameHeader.getAttribute("aria-sort")).toBe("none");
    fireEvent.click(screen.getByRole("button", { name: /Name/ }));
    expect(names()).toEqual(["Aroha", "Lee", "Tama"]);
    expect(nameHeader.getAttribute("aria-sort")).toBe("ascending");
    fireEvent.click(screen.getByRole("button", { name: /Name/ }));
    expect(names()).toEqual(["Tama", "Lee", "Aroha"]);
  });

  it("starts a column at its natural direction and sorts empties last", () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Joined" }));
    expect(names()).toEqual(["Lee", "Aroha", "Tama"]);
    expect(screen.getByRole("columnheader", { name: /Joined/ }).getAttribute("aria-sort")).toBe(
      "descending",
    );
  });

  it("leaves a column without a sort key as a plain heading", () => {
    render(<Harness />);
    const note = screen.getByRole("columnheader", { name: "Note" });
    expect(note.getAttribute("aria-sort")).toBeNull();
    expect(within(note).queryByRole("button")).toBeNull();
  });
});

describe("Field", () => {
  it("wraps its control in a label by default", () => {
    render(
      <Field label="Invitee DID" hint="A did:key or did:webvh">
        <input />
      </Field>,
    );
    const input = screen.getByLabelText("Invitee DID");
    expect(input.closest(".field")?.tagName).toBe("DIV");
    // The hint is not part of the control's name.
    expect(screen.getByText("A did:key or did:webvh").className).toBe("field-hint");
    expect(screen.getByText("A did:key or did:webvh").closest("label")).toBeNull();
  });

  it("is the label itself when there is no hint or error", () => {
    render(
      <Field label="Role">
        <select />
      </Field>,
    );
    expect(screen.getByLabelText("Role").closest("label")?.className).toBe("field");
  });

  it("points at its control by id, with a described error", () => {
    render(
      <Field label="Name" htmlFor="n" error="Required" errorId="n-err" errorRole="alert" inline>
        <input id="n" aria-describedby="n-err" />
      </Field>,
    );
    const input = screen.getByLabelText("Name");
    expect(input.closest(".field")?.className).toBe("field inline");
    expect(screen.getByRole("alert").id).toBe("n-err");
  });
});

describe("EmptyState", () => {
  it("names what is absent, with a reason and an action", () => {
    render(
      <EmptyState icon={Inbox} title="No join requests" action={<button>Invite</button>}>
        New requests appear here.
      </EmptyState>,
    );
    expect(screen.getByRole("heading", { name: "No join requests" })).toBeTruthy();
    expect(screen.getByText("New requests appear here.")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Invite" })).toBeTruthy();
  });

  it("has a one-line form for inside a card", () => {
    const { container } = render(<EmptyState compact title="None enrolled." />);
    expect(container.querySelector("p.empty-state.compact")?.textContent).toBe("None enrolled.");
    expect(screen.queryByRole("heading")).toBeNull();
  });
});
