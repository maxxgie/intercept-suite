import { useStore } from "../state/store";
import { MORE_TOOLS, NAV_GROUPS, type NavItem } from "./navigation";
import { IconPanelLeft } from "./icons";

function NavButton({ item }: { item: NavItem }) {
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const total = useStore((s) => s.total);
  const findings = useStore((s) => s.findings);
  const issues = useStore((s) => s.issues);
  const heldRequests = useStore((s) => s.heldRequests);

  const counts: Partial<Record<string, number>> = {
    traffic: total,
    findings: findings.filter((finding) => !finding.acknowledged).length,
    issues: issues.filter((issue) => issue.status === "open").length,
    intercept: heldRequests.length,
  };

  const count = counts[item.id] ?? 0;
  const Icon = item.icon;

  return (
    <button
      className={view === item.id ? "nav-item active" : "nav-item"}
      onClick={() => setView(item.id)}
      title={item.hint}
    >
      <Icon size={15} />
      <span className="nav-label">{item.label}</span>
      {count > 0 && <span className="nav-count">{count}</span>}
    </button>
  );
}

/**
 * The tool navigation. It is grouped the way the work is done, and it can be
 * folded away to give the workspace the whole window.
 */
export default function Sidebar() {
  const collapsed = useStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useStore((s) => s.toggleSidebar);

  return (
    <nav className={collapsed ? "nav collapsed" : "nav"}>
      <button
        className="nav-collapse"
        onClick={toggleSidebar}
        title={collapsed ? "Show the navigation" : "Hide the navigation"}
        aria-label={collapsed ? "Show the navigation" : "Hide the navigation"}
      >
        <IconPanelLeft size={15} />
      </button>

      <div className="nav-scroll">
        {NAV_GROUPS.map((group) => (
          <div className="nav-group" key={group.name}>
            <div className="nav-group-name">{group.name}</div>
            {group.items.map((item) => (
              <NavButton item={item} key={item.id} />
            ))}
          </div>
        ))}

        <div className="nav-group">
          <div className="nav-group-name">More</div>
          {MORE_TOOLS.map((item) => (
            <NavButton item={item} key={item.id} />
          ))}
        </div>
      </div>
    </nav>
  );
}
