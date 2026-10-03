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
  BadgeCheck,
  ClipboardList,
  DoorOpen,
  FolderGit2,
  Inbox,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  Network,
  PenLine,
  Share2,
  ShieldCheck,
  Smartphone,
  Tag,
  Ticket,
  UserCog,
  Users,
  Workflow,
} from "lucide-react";

import { ACTIONS_PLUGIN_ID } from "@/lib/action-badge";
import { registerPlugin } from "@/plugin-api";
import { Acl } from "@/plugins/acl";
import { Actions } from "@/plugins/actions";
import { Audit } from "@/plugins/audit";
import { Ceremonies } from "@/plugins/ceremonies";
import { ConsoleKeys } from "@/plugins/consoleKeys";
import { Dashboard } from "@/plugins/dashboard";
import { Invitations } from "@/plugins/invitations";
import { JoinRequests } from "@/plugins/joinRequests";
import { Members } from "@/plugins/members";
import { MyPasskeys } from "@/plugins/myPasskeys";
import { Profile } from "@/plugins/profile";
import { Recognition } from "@/plugins/recognition";
import { Relationships } from "@/plugins/relationshipsGraph";
import { Repos } from "@/plugins/repos";
import { Roles } from "@/plugins/roles";
import { Rooms } from "@/plugins/rooms";
import { Sessions } from "@/plugins/sessions";
import { Vetting } from "@/plugins/vetting";

export function registerBuiltinPlugins(): void {
  registerPlugin({
    id: "dashboard",
    label: "Dashboard",
    path: "/",
    iconComponent: LayoutDashboard,
    reactComponent: Dashboard,
  });

  // The administrator action list. Its nav badge (the count waiting for you)
  // is drawn by the shell (`App.tsx`, `lib/action-badge.ts`).
  registerPlugin({
    id: ACTIONS_PLUGIN_ID,
    label: "Actions",
    path: "/actions",
    iconComponent: ListChecks,
    reactComponent: Actions,
  });

  registerPlugin({
    id: "ceremonies",
    label: "Ceremonies",
    path: "/ceremonies",
    iconComponent: Workflow,
    reactComponent: Ceremonies,
  });

  registerPlugin({
    id: "join-requests",
    label: "Join requests",
    path: "/join-requests",
    iconComponent: Inbox,
    reactComponent: JoinRequests,
    capabilities: ["vtc.join.decide"],
  });

  registerPlugin({
    id: "vetting",
    label: "Vetting",
    path: "/vetting",
    iconComponent: BadgeCheck,
    reactComponent: Vetting,
    capabilities: ["vtc.vetting.manage"],
  });

  registerPlugin({
    id: "invitations",
    label: "Invitations",
    path: "/invitations",
    iconComponent: Ticket,
    reactComponent: Invitations,
    capabilities: ["vtc.invitations.manage"],
  });

  registerPlugin({
    id: "recognition",
    label: "Recognition",
    path: "/recognition",
    iconComponent: Network,
    reactComponent: Recognition,
    capabilities: ["vtc.registry.admin"],
  });

  registerPlugin({
    id: "relationships",
    label: "Relationships",
    path: "/relationships",
    iconComponent: Share2,
    reactComponent: Relationships,
  });

  registerPlugin({
    id: "members",
    label: "Members",
    path: "/members",
    iconComponent: Users,
    reactComponent: Members,
    capabilities: ["vtc.members.manage"],
  });

  registerPlugin({
    id: "rooms",
    label: "Data rooms",
    path: "/rooms",
    iconComponent: DoorOpen,
    reactComponent: Rooms,
  });

  registerPlugin({
    id: "repos",
    label: "Repos",
    path: "/repos",
    iconComponent: FolderGit2,
    reactComponent: Repos,
    // Git-namespace rights are capabilities on the ACL entry (phase C3): the
    // page is for whoever administers a namespace or manages a repository —
    // at any qualifier — and a community administrator, whose `git.ns.admin`
    // is community-wide.
    capabilities: ["git.ns.admin", "git.repo.manage"],
  });

  registerPlugin({
    id: "acl",
    label: "Access control",
    path: "/acl",
    iconComponent: ShieldCheck,
    reactComponent: Acl,
  });

  // The administrative role vocabulary: readable by every administrator,
  // defined and deleted (through the action list) by holders of
  // vtc.roles.assign and vtc.approvals.admin (`vtc-admin-roles.md` §6.2).
  registerPlugin({
    id: "roles",
    label: "Roles",
    path: "/roles",
    iconComponent: UserCog,
    reactComponent: Roles,
  });

  registerPlugin({
    id: "profile",
    label: "Community profile",
    path: "/profile",
    iconComponent: Tag,
    reactComponent: Profile,
    capabilities: ["vtc.surface.admin"],
  });

  registerPlugin({
    id: "my-passkeys",
    label: "My passkeys",
    path: "/my-passkeys",
    iconComponent: KeyRound,
    reactComponent: MyPasskeys,
  });

  registerPlugin({
    id: "console-keys",
    label: "Signing keys",
    path: "/console-keys",
    iconComponent: PenLine,
    reactComponent: ConsoleKeys,
  });

  registerPlugin({
    id: "sessions",
    label: "Sessions",
    path: "/sessions",
    iconComponent: Smartphone,
    reactComponent: Sessions,
    capabilities: ["vtc.sessions.revoke"],
  });

  registerPlugin({
    id: "audit",
    label: "Audit trail",
    path: "/audit",
    iconComponent: ClipboardList,
    reactComponent: Audit,
    capabilities: ["vtc.audit.read"],
  });
}
