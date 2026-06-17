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
  ClipboardList,
  Inbox,
  KeyRound,
  LayoutDashboard,
  Network,
  ShieldCheck,
  Smartphone,
  Tag,
  Ticket,
  Users,
  Workflow,
} from "lucide-react";

import { registerPlugin } from "@/plugin-api";
import { Acl } from "@/plugins/acl";
import { Audit } from "@/plugins/audit";
import { Ceremonies } from "@/plugins/ceremonies";
import { Dashboard } from "@/plugins/dashboard";
import { Invitations } from "@/plugins/invitations";
import { JoinRequests } from "@/plugins/joinRequests";
import { Members } from "@/plugins/members";
import { MyPasskeys } from "@/plugins/myPasskeys";
import { Profile } from "@/plugins/profile";
import { Recognition } from "@/plugins/recognition";
import { Sessions } from "@/plugins/sessions";

export function registerBuiltinPlugins(): void {
  registerPlugin({
    id: "dashboard",
    label: "Dashboard",
    path: "/",
    iconComponent: LayoutDashboard,
    reactComponent: Dashboard,
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
  });

  registerPlugin({
    id: "invitations",
    label: "Invitations",
    path: "/invitations",
    iconComponent: Ticket,
    reactComponent: Invitations,
  });

  registerPlugin({
    id: "recognition",
    label: "Recognition",
    path: "/recognition",
    iconComponent: Network,
    reactComponent: Recognition,
  });

  registerPlugin({
    id: "members",
    label: "Members",
    path: "/members",
    iconComponent: Users,
    reactComponent: Members,
  });

  registerPlugin({
    id: "acl",
    label: "Access control",
    path: "/acl",
    iconComponent: ShieldCheck,
    reactComponent: Acl,
  });

  registerPlugin({
    id: "profile",
    label: "Community profile",
    path: "/profile",
    iconComponent: Tag,
    reactComponent: Profile,
  });

  registerPlugin({
    id: "my-passkeys",
    label: "My passkeys",
    path: "/my-passkeys",
    iconComponent: KeyRound,
    reactComponent: MyPasskeys,
  });

  registerPlugin({
    id: "sessions",
    label: "Sessions",
    path: "/sessions",
    iconComponent: Smartphone,
    reactComponent: Sessions,
    scopes: ["super-admin"],
  });

  registerPlugin({
    id: "audit",
    label: "Audit trail",
    path: "/audit",
    iconComponent: ClipboardList,
    reactComponent: Audit,
    scopes: ["super-admin"],
  });
}
