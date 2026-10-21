import type { SVGProps } from "react";

/**
 * A small inline icon set.
 *
 * The icons are drawn here rather than pulled from a package so the shell
 * stays free of runtime dependencies and every glyph shares the same stroke
 * weight and grid.
 */

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Glyph({ size = 15, children, ...rest }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconDashboard = (props: IconProps) => (
  <Glyph {...props}>
    <rect x="3" y="3" width="7" height="9" rx="1" />
    <rect x="14" y="3" width="7" height="5" rx="1" />
    <rect x="14" y="12" width="7" height="9" rx="1" />
    <rect x="3" y="16" width="7" height="5" rx="1" />
  </Glyph>
);

export const IconActivity = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M3 12h4l3 7 4-14 3 7h4" />
  </Glyph>
);

export const IconRadar = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="12" cy="12" r="9" />
    <circle cx="12" cy="12" r="5" />
    <path d="M12 12 19 7" />
    <circle cx="12" cy="12" r="1" />
  </Glyph>
);

export const IconIntercept = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M4 7h10" />
    <path d="M4 12h6" />
    <path d="M4 17h10" />
    <circle cx="18" cy="8" r="3" />
    <path d="M20.5 10.5 22 12" />
  </Glyph>
);

export const IconHistory = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </Glyph>
);

export const IconWebsocket = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M4 18 8 6l4 9 4-9 4 12" />
  </Glyph>
);

export const IconSitemap = (props: IconProps) => (
  <Glyph {...props}>
    <rect x="9" y="3" width="6" height="4" rx="1" />
    <rect x="3" y="16" width="6" height="4" rx="1" />
    <rect x="15" y="16" width="6" height="4" rx="1" />
    <path d="M12 7v4M6 16v-2h12v2" />
  </Glyph>
);

export const IconScope = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="12" cy="12" r="8" />
    <circle cx="12" cy="12" r="3" />
    <path d="M12 2v3M12 19v3M2 12h3M19 12h3" />
  </Glyph>
);

export const IconEndpoints = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M6 4v6a4 4 0 0 0 4 4h8" />
    <circle cx="6" cy="4" r="2" />
    <circle cx="18" cy="14" r="2" />
  </Glyph>
);

export const IconRepeater = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M4 8h11l-3-3" />
    <path d="M20 16H9l3 3" />
  </Glyph>
);

export const IconIntruder = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M3 12h4l2-6 4 12 2-6h6" />
  </Glyph>
);

export const IconBuilder = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M14 4 20 10l-9 9H5v-6z" />
    <path d="m12 6 2 2M10 8l2 2" />
  </Glyph>
);

export const IconScanner = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3" />
    <path d="M4 12h16" />
  </Glyph>
);

export const IconFindings = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M12 3 4 6v6c0 5 3.4 8.4 8 9 4.6-.6 8-4 8-9V6z" />
    <path d="M12 9v4M12 16.5v.5" />
  </Glyph>
);

export const IconDecoder = (props: IconProps) => (
  <Glyph {...props}>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M7 9h3M8 8v2M14 9h3M17 9h.01" />
    <path d="M7 14h10" />
  </Glyph>
);

export const IconComparer = (props: IconProps) => (
  <Glyph {...props}>
    <rect x="3" y="4" width="8" height="16" rx="1" />
    <rect x="13" y="4" width="8" height="16" rx="1" />
    <path d="M6 9h2M6 13h2M16 9h2M16 13h2" />
  </Glyph>
);

export const IconTokens = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="8" cy="12" r="4" />
    <path d="M12 12h9M17 12l-2-2M17 12l-2 2M21 12l-2-2M21 12l-2 2" />
  </Glyph>
);

export const IconLogger = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M5 4h14v16H5z" />
    <path d="M8 9h8M8 13h8M8 17h5" />
  </Glyph>
);

export const IconSettings = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 9 19.4a1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 4.6 9a1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z" />
  </Glyph>
);

export const IconExtensions = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M9 3v4M15 3v4" />
    <path d="M7 7h10v4a5 5 0 0 1-10 0z" />
    <path d="M12 16v5" />
  </Glyph>
);

export const IconReport = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M6 3h8l4 4v14H6z" />
    <path d="M14 3v4h4" />
    <path d="M9 13h6M9 17h6" />
  </Glyph>
);

export const IconExport = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M12 16V4M8 8l4-4 4 4" />
    <path d="M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3" />
  </Glyph>
);

export const IconFolder = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M3 7a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z" />
  </Glyph>
);

export const IconSave = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M5 3h11l3 3v15H5z" />
    <path d="M8 3v6h7V3M8 21v-6h8v6" />
  </Glyph>
);

export const IconSearch = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="11" cy="11" r="6" />
    <path d="m20 20-4.5-4.5" />
  </Glyph>
);

export const IconPlay = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M7 4l12 8-12 8z" />
  </Glyph>
);

export const IconStop = (props: IconProps) => (
  <Glyph {...props}>
    <rect x="6" y="6" width="12" height="12" rx="1" />
  </Glyph>
);

export const IconTrash = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13" />
  </Glyph>
);

export const IconChevron = (props: IconProps) => (
  <Glyph {...props}>
    <path d="m9 6 6 6-6 6" />
  </Glyph>
);

export const IconClose = (props: IconProps) => (
  <Glyph {...props}>
    <path d="m6 6 12 12M18 6 6 18" />
  </Glyph>
);

export const IconPanelLeft = (props: IconProps) => (
  <Glyph {...props}>
    <rect x="3" y="4" width="18" height="16" rx="1" />
    <path d="M9 4v16" />
  </Glyph>
);

export const IconPanelBottom = (props: IconProps) => (
  <Glyph {...props}>
    <rect x="3" y="4" width="18" height="16" rx="1" />
    <path d="M3 15h18" />
  </Glyph>
);

export const IconBroom = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M14 3 9 8M6 21l3-7 7-7 4 4-7 7z" />
    <path d="M4 21h5" />
  </Glyph>
);

export const IconSpider = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="12" cy="12" r="3" />
    <path d="M12 9V4M12 15v5M9 12H4M15 12h5M10 10 7 7M14 14l3 3M14 10l3-3M10 14l-3 3" />
  </Glyph>
);

export const IconIssue = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 8v5M12 16v.5" />
  </Glyph>
);

export const IconNote = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M5 4h14v16H5z" />
    <path d="M9 9h6M9 13h6M9 17h3" />
  </Glyph>
);

export const IconTarget = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="12" cy="12" r="9" />
    <circle cx="12" cy="12" r="5" />
    <circle cx="12" cy="12" r="1.5" />
  </Glyph>
);

export const IconClock = (props: IconProps) => (
  <Glyph {...props}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </Glyph>
);

export const IconBrowser = (props: IconProps) => (
  <Glyph {...props}>
    <rect x="3" y="4" width="18" height="16" rx="1" />
    <path d="M3 9h18" />
    <circle cx="6.5" cy="6.5" r="0.6" fill="currentColor" />
  </Glyph>
);

export const IconOrganizer = (props: IconProps) => (
  <Glyph {...props}>
    <path d="M4 5h6v6H4zM14 5h6v6h-6zM4 14h6v5H4zM14 14h6v5h-6z" />
  </Glyph>
);
