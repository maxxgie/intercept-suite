import type { ComponentType, SVGProps } from "react";
import {
  IconActivity,
  IconBrowser,
  IconBroom,
  IconBuilder,
  IconClock,
  IconComparer,
  IconDashboard,
  IconDecoder,
  IconEndpoints,
  IconExport,
  IconExtensions,
  IconFindings,
  IconFolder,
  IconHistory,
  IconIntercept,
  IconIntruder,
  IconIssue,
  IconLogger,
  IconNote,
  IconOrganizer,
  IconRadar,
  IconReport,
  IconRepeater,
  IconScanner,
  IconScope,
  IconSequencer,
  IconSettings,
  IconSitemap,
  IconTarget,
  IconTokens,
  IconWebsocket,
} from "./icons";
import type { View } from "../state/store";

export type IconComponent = ComponentType<SVGProps<SVGSVGElement> & { size?: number }>;

export interface NavItem {
  id: View;
  label: string;
  icon: IconComponent;
  hint: string;
}

export interface NavGroup {
  name: string;
  items: NavItem[];
}

/**
 * The tool navigation, grouped the way the work is done.
 */
export const NAV_GROUPS: NavGroup[] = [
  {
    name: "Dashboard",
    items: [
      {
        id: "dashboard",
        label: "Overview",
        icon: IconDashboard,
        hint: "Everything the engagement produced so far",
      },
      {
        id: "activity",
        label: "Activity",
        icon: IconActivity,
        hint: "What happened, in the order it happened",
      },
      {
        id: "scan-status",
        label: "Scan status",
        icon: IconRadar,
        hint: "The scans and fuzz jobs that are running",
      },
    ],
  },
  {
    name: "Proxy",
    items: [
      {
        id: "intercept",
        label: "Intercept",
        icon: IconIntercept,
        hint: "Hold requests and decide what happens to them",
      },
      {
        id: "rules",
        label: "Proxy Rules",
        icon: IconBroom,
        hint: "What to hold, what to let through and what to rewrite",
      },
      {
        id: "traffic",
        label: "HTTP History",
        icon: IconHistory,
        hint: "Every exchange the proxy has seen",
      },
      {
        id: "websockets",
        label: "WebSocket History",
        icon: IconWebsocket,
        hint: "The connections that were upgraded and their frames",
      },
    ],
  },
  {
    name: "Target",
    items: [
      {
        id: "sites",
        label: "Site Map",
        icon: IconSitemap,
        hint: "The hosts and paths that have been discovered",
      },
      {
        id: "scope",
        label: "Scope",
        icon: IconScope,
        hint: "The rules that decide what may be visited",
      },
      {
        id: "endpoints",
        label: "Discovered endpoints",
        icon: IconEndpoints,
        hint: "Every path that was seen, in one table",
      },
    ],
  },
  {
    name: "Testing",
    items: [
      {
        id: "repeater",
        label: "Repeater",
        icon: IconRepeater,
        hint: "Edit a request and resend it",
      },
      {
        id: "fuzzer",
        label: "Intruder / Fuzzer",
        icon: IconIntruder,
        hint: "Send many payloads at one request",
      },
      {
        id: "builder",
        label: "Request Builder",
        icon: IconBuilder,
        hint: "Write a request from scratch",
      },
    ],
  },
  {
    name: "Analysis",
    items: [
      {
        id: "scanner",
        label: "Scanner",
        icon: IconScanner,
        hint: "Run checks against a target",
      },
      {
        id: "findings",
        label: "Vulnerability Findings",
        icon: IconFindings,
        hint: "Everything the scanner reported",
      },
      {
        id: "decoder",
        label: "Decoder",
        icon: IconDecoder,
        hint: "Encode and decode payloads",
      },
      {
        id: "comparer",
        label: "Comparer",
        icon: IconComparer,
        hint: "Put two exchanges side by side",
      },
      {
        id: "tokens",
        label: "Token Analysis",
        icon: IconTokens,
        hint: "Look for tokens and secrets in a message",
      },
      {
        id: "sequencer",
        label: "Sequencer",
        icon: IconSequencer,
        hint: "Judge how random a token really is",
      },
    ],
  },
  {
    name: "Utilities",
    items: [
      {
        id: "logger",
        label: "Logger",
        icon: IconLogger,
        hint: "Everything the daemon did",
      },
      {
        id: "settings",
        label: "Settings",
        icon: IconSettings,
        hint: "Proxy, certificate authority and trust stores",
      },
      {
        id: "extensions",
        label: "Extensions",
        icon: IconExtensions,
        hint: "The tools contributed by plugins",
      },
    ],
  },
  {
    name: "Reports",
    items: [
      {
        id: "reports",
        label: "Vulnerability Reports",
        icon: IconReport,
        hint: "Findings, issues and notes as one document",
      },
      {
        id: "export",
        label: "Export Results",
        icon: IconExport,
        hint: "Take the results out of the tool",
      },
    ],
  },
];

/**
 * The tools that do not belong to one of the groups above are kept here, so
 * nothing that used to be reachable becomes unreachable.
 */
export const MORE_TOOLS: NavItem[] = [
  { id: "issues", label: "Issue tracker", icon: IconIssue, hint: "The problems that were raised" },
  { id: "notes", label: "Notes", icon: IconNote, hint: "Remarks and highlights" },
  { id: "organizer", label: "Organizer", icon: IconOrganizer, hint: "Traffic grouped by host" },
  { id: "targets", label: "Targets", icon: IconTarget, hint: "The hosts under test" },
  { id: "tasks", label: "Task scheduler", icon: IconClock, hint: "Commands on an interval" },
  { id: "projects", label: "Project files", icon: IconFolder, hint: "Saved engagements" },
  { id: "browser", label: "Browser", icon: IconBrowser, hint: "Fetch a page through the proxy" },
];

export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((group) => group.items);
