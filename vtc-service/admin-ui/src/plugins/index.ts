// Built-in plugin registry.
//
// Each first-party plugin lives in its own folder under
// `src/plugins/` and registers itself with the shell here. New
// plugins follow the same shape: write a React component, add a
// `registerPlugin({...})` call below.
//
// Third-party plugins use the same `window.VtcPluginApi
// .registerPlugin` API but call it from their own bundle loaded
// dynamically by the shell. Treating built-ins as plugins
// validates the API every build — if writing a built-in feels
// awkward, the API is wrong.

import {
  Award,
  BadgeCheck,
  Bell,
  BookUser,
  ClipboardList,
  Vote,
  DoorOpen,
  FolderGit2,
  Inbox,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  Network,
  Waypoints,
  PenLine,
  ScanLine,
  Share2,
  SquareKanban,
  ShieldCheck,
  Smartphone,
  Tag,
  Ticket,
  UserCog,
  Users,
  UsersRound,
  Workflow,
} from "lucide-react";

import { ACTIONS_PLUGIN_ID } from "@/lib/action-badge";
import { registerPlugin } from "@/plugin-api";
import { Acl } from "@/plugins/acl";
import { Actions } from "@/plugins/actions";
import { Audit } from "@/plugins/audit";
import { Badges } from "@/plugins/badges";
import { Boards } from "@/plugins/boards";
import { Ceremonies } from "@/plugins/ceremonies";
import { ConsoleKeys } from "@/plugins/consoleKeys";
import { Dashboard } from "@/plugins/dashboard";
import { DATA_ROOMS_CAPABILITIES, DataRooms } from "@/plugins/dataRooms";
import { Directory } from "@/plugins/directory";
import { Elections } from "@/plugins/elections";
import { Groups } from "@/plugins/groups";
import { Invitations } from "@/plugins/invitations";
import { JoinRequests } from "@/plugins/joinRequests";
import { Members } from "@/plugins/members";
import { MyPasskeys } from "@/plugins/myPasskeys";
import { Networks } from "@/plugins/networks";
import { Notifications } from "@/plugins/notifications";
import { Profile } from "@/plugins/profile";
import { Recognition } from "@/plugins/recognition";
import { Relationships } from "@/plugins/relationshipsGraph";
import { Repos } from "@/plugins/repos";
import { Roles } from "@/plugins/roles";
import { Sessions } from "@/plugins/sessions";
import { Vetting } from "@/plugins/vetting";
import { WalletVerifier } from "@/plugins/walletVerifier";

export function registerBuiltinPlugins(): void {
  // ── Overview ──
  registerPlugin({
    id: "dashboard",
    group: "overview",
    label: "Dashboard",
    path: "/",
    iconComponent: LayoutDashboard,
    reactComponent: Dashboard,
  });

  // The administrator action list. Its nav badge (the count waiting for you)
  // is drawn by the shell (`App.tsx`, `lib/action-badge.ts`).
  registerPlugin({
    id: ACTIONS_PLUGIN_ID,
    group: "overview",
    label: "Actions",
    path: "/actions",
    iconComponent: ListChecks,
    reactComponent: Actions,
    // Takes the community theme; its decision surfaces (each card that
    // decides, the confirmations, the dialogs) are drawn out of the theme's
    // reach where they render (`components/Protected.tsx`).
  });

  registerPlugin({
    id: "audit",
    group: "overview",
    label: "Audit trail",
    path: "/audit",
    iconComponent: ClipboardList,
    reactComponent: Audit,
    capabilities: ["vtc.audit.read"],
  });

  // ── Membership ──
  registerPlugin({
    id: "join-requests",
    group: "membership",
    label: "Join requests",
    path: "/join-requests",
    iconComponent: Inbox,
    reactComponent: JoinRequests,
    // Takes the community theme; its decision surfaces (each card that
    // decides, the confirmations, the dialogs) are drawn out of the theme's
    // reach where they render (`components/Protected.tsx`).
    capabilities: ["vtc.join.decide"],
  });

  registerPlugin({
    id: "members",
    group: "membership",
    label: "Members",
    path: "/members",
    iconComponent: Users,
    reactComponent: Members,
    // Takes the community theme; its decision surfaces (each card that
    // decides, the confirmations, the dialogs) are drawn out of the theme's
    // reach where they render (`components/Protected.tsx`).
    capabilities: ["vtc.members.manage"],
  });

  // The member directory: its fields, and every member's entry as an
  // administrator reads it. Any administrator reads; holders of
  // vtc.directory.admin change the schema and assert values.
  registerPlugin({
    id: "directory",
    group: "membership",
    label: "Directory",
    path: "/directory",
    iconComponent: BookUser,
    reactComponent: Directory,
  });

  // The community's polls, surveys and elections (docs/03-vtc/elections.md):
  // create, close, cancel and certify them. Members vote through their own VTA.
  registerPlugin({
    id: "elections",
    group: "governance",
    label: "Elections",
    path: "/elections",
    iconComponent: Vote,
    reactComponent: Elections,
    capabilities: ["vtc.elections.manage"],
  });

  // Community boards: facilitators (vtc.boards.manage, for every board or
  // qualified to one) decide ideas, select among them and hide notes. Members
  // propose and leave notes from the member portal.
  registerPlugin({
    id: "boards",
    group: "governance",
    label: "Boards",
    path: "/boards",
    iconComponent: SquareKanban,
    reactComponent: Boards,
    capabilities: ["vtc.boards.manage"],
  });

  // The community's groups: every administrator reads them; holders of
  // vtc.groups.manage create them, and each group's managers run it.
  registerPlugin({
    id: "groups",
    group: "membership",
    label: "Groups",
    path: "/groups",
    iconComponent: UsersRound,
    reactComponent: Groups,
  });

  registerPlugin({
    id: "invitations",
    group: "membership",
    label: "Invitations",
    path: "/invitations",
    iconComponent: Ticket,
    reactComponent: Invitations,
    capabilities: ["vtc.invitations.manage"],
  });

  registerPlugin({
    id: "vetting",
    group: "membership",
    label: "Vetting",
    path: "/vetting",
    iconComponent: BadgeCheck,
    reactComponent: Vetting,
    capabilities: ["vtc.vetting.manage"],
  });

  registerPlugin({
    id: "relationships",
    group: "membership",
    label: "Relationships",
    path: "/relationships",
    iconComponent: Share2,
    reactComponent: Relationships,
  });

  // Notifications the community holds as their addressee (an election another
  // community holds, say), and the decision to relay one to members
  // (vtc/notifications/*, VTI-NTF-070 – 074).
  registerPlugin({
    id: "notifications",
    group: "membership",
    label: "Notifications",
    path: "/notifications",
    iconComponent: Bell,
    reactComponent: Notifications,
    capabilities: ["vtc.notifications.read"],
  });

  // ── Governance ──
  // Shown as "Policies": the label changed, the route did not.
  registerPlugin({
    id: "ceremonies",
    group: "governance",
    label: "Policies",
    path: "/ceremonies",
    iconComponent: Workflow,
    reactComponent: Ceremonies,
  });

  // The administrative role vocabulary: readable by every administrator,
  // defined and deleted (through the action list) by holders of
  // vtc.roles.assign and vtc.approvals.admin (`vtc-admin-roles.md` §6.2).
  registerPlugin({
    id: "roles",
    group: "governance",
    label: "Roles",
    path: "/roles",
    iconComponent: UserCog,
    reactComponent: Roles,
  });

  registerPlugin({
    id: "acl",
    group: "governance",
    label: "Access control",
    path: "/acl",
    iconComponent: ShieldCheck,
    reactComponent: Acl,
  });

  registerPlugin({
    id: "sessions",
    group: "governance",
    label: "Sessions",
    path: "/sessions",
    iconComponent: Smartphone,
    reactComponent: Sessions,
    capabilities: ["vtc.sessions.revoke"],
  });

  // ── Community ──
  registerPlugin({
    id: "profile",
    group: "community",
    label: "Profile",
    path: "/profile",
    iconComponent: Tag,
    reactComponent: Profile,
    capabilities: ["vtc.surface.admin"],
  });

  registerPlugin({
    id: "recognition",
    group: "community",
    label: "Recognition",
    path: "/recognition",
    iconComponent: Network,
    reactComponent: Recognition,
    capabilities: ["vtc.registry.admin"],
  });

  // The Verifiable Trust Networks this community belongs to (`vtc/networks/*`,
  // docs/03-vtc/networks.md): join from a network's invitation
  // (`/admin/networks?join=<url>&network=<did>`), leave, or reject a listing.
  registerPlugin({
    id: "networks",
    group: "community",
    label: "Networks",
    path: "/networks",
    iconComponent: Waypoints,
    reactComponent: Networks,
    capabilities: ["vtc.config.admin"],
  });

  // Member badges (docs/03-vtc/badges.md): holders of vtc.badges.admin define
  // community badges and give any badge; a badge's owners (the managers of
  // its badge group, vtc.groups.manage qualified to it) give theirs; holders
  // of vtc.config.admin turn badges on and set the limits. Members hold,
  // show and give kudos from the member portal.
  registerPlugin({
    id: "badges",
    group: "community",
    label: "Badges",
    path: "/badges",
    iconComponent: Award,
    reactComponent: Badges,
    capabilities: ["vtc.badges.admin", "vtc.groups.manage", "vtc.config.admin"],
  });

  registerPlugin({
    id: "wallet-verifier",
    group: "community",
    label: "Wallet verifier",
    path: "/wallet-verifier",
    iconComponent: ScanLine,
    reactComponent: WalletVerifier,
    capabilities: ["vtc.config.admin"],
  });

  // One entry for data rooms: Rooms, Usage and Storage are tabs of it
  // (`plugins/dataRooms.tsx`), each gated on its own capability. The entry is
  // shown to a holder of any of them, so a tab for another authority adds its
  // capability to the entry by being listed there.
  registerPlugin({
    id: "rooms",
    group: "community",
    label: "Data rooms",
    path: "/rooms",
    iconComponent: DoorOpen,
    reactComponent: DataRooms,
    capabilities: DATA_ROOMS_CAPABILITIES,
  });

  registerPlugin({
    id: "repos",
    group: "community",
    label: "Repos",
    path: "/repos",
    iconComponent: FolderGit2,
    reactComponent: Repos,
    // Takes the community theme; its decision surfaces (each card that
    // decides, the confirmations, the dialogs) are drawn out of the theme's
    // reach where they render (`components/Protected.tsx`).
    // Git-namespace rights are capabilities on the ACL entry (phase C3): the
    // page is for whoever administers a namespace or manages a repository —
    // at any qualifier — and a community administrator, whose `git.ns.admin`
    // is community-wide.
    capabilities: ["git.ns.admin", "git.repo.manage"],
  });

  // ── Account menu (top bar): the operator's own, not the community's ──
  registerPlugin({
    id: "my-passkeys",
    group: "account",
    label: "My passkeys",
    path: "/my-passkeys",
    iconComponent: KeyRound,
    reactComponent: MyPasskeys,
  });

  registerPlugin({
    id: "console-keys",
    group: "account",
    label: "Signing keys",
    path: "/console-keys",
    iconComponent: PenLine,
    reactComponent: ConsoleKeys,
  });
}
