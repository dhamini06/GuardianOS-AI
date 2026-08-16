import { Link, useLocation } from "react-router";
import {
  AlertHexaIcon,
  BoltIcon,
  BoxCubeIcon,
  GridIcon,
  ListIcon,
  PieChartIcon,
  PlugInIcon,
  TableIcon,
  UserCircleIcon,
} from "../icons";
import { useSidebar } from "../context/SidebarContext";
import Brand from "../components/Brand";

type NavItem = {
  name: string;
  icon: React.ReactNode;
  path: string;
  badge?: string;
};

const navItems: NavItem[] = [
  { name: "Overview", icon: <GridIcon />, path: "/" },
  { name: "Threats", icon: <AlertHexaIcon />, path: "/threats" },
  { name: "Kernel Activity", icon: <BoltIcon />, path: "/kernel" },
  { name: "Processes", icon: <ListIcon />, path: "/processes" },
  { name: "AI Analysis", icon: <PieChartIcon />, path: "/analysis" },
  { name: "Response", icon: <BoxCubeIcon />, path: "/response" },
  { name: "System Health", icon: <TableIcon />, path: "/health" },
  { name: "Settings", icon: <UserCircleIcon />, path: "/settings" },
];

const AppSidebar: React.FC = () => {
  const { isExpanded, isMobileOpen, isHovered, setIsHovered } = useSidebar();
  const location = useLocation();

  const isActive = (path: string) =>
    path === "/" ? location.pathname === "/" : location.pathname.startsWith(path);

  return (
    <aside
      className={`fixed mt-16 flex flex-col lg:mt-0 top-0 px-5 left-0 bg-white dark:bg-gray-900 dark:border-gray-800 text-gray-900 h-screen transition-all duration-300 ease-in-out z-50 border-r border-gray-200 
        ${
          isExpanded || isMobileOpen
            ? "w-[290px]"
            : isHovered
              ? "w-[290px]"
              : "w-[90px]"
        }
        ${isMobileOpen ? "translate-x-0" : "-translate-x-full"}
        lg:translate-x-0`}
      onMouseEnter={() => !isExpanded && setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <div
        className={`py-8 flex ${
          !isExpanded && !isHovered ? "lg:justify-center" : "justify-start"
        }`}
      >
        <Link to="/" aria-label="GuardianOS-AI home">
          {isExpanded || isHovered || isMobileOpen ? (
            <Brand />
          ) : (
            <Brand compact />
          )}
        </Link>
      </div>
      <nav className="flex flex-col overflow-y-auto duration-300 ease-linear no-scrollbar">
        <ul className="flex flex-col gap-1">
          {navItems.map((nav) => (
            <li key={nav.path}>
              <Link
                to={nav.path}
                className={`menu-item group ${
                  isActive(nav.path) ? "menu-item-active" : "menu-item-inactive"
                }`}
              >
                <span
                  className={`menu-item-icon-size ${
                    isActive(nav.path)
                      ? "menu-item-icon-active"
                      : "menu-item-icon-inactive"
                  }`}
                >
                  {nav.icon}
                </span>
                {(isExpanded || isHovered || isMobileOpen) && (
                  <span className="menu-item-text">{nav.name}</span>
                )}
                {nav.badge && (isExpanded || isHovered || isMobileOpen) && (
                  <span className="ml-auto rounded-md bg-brand-500/10 px-2 py-0.5 text-[10px] font-semibold text-brand-500 dark:text-brand-400">
                    {nav.badge}
                  </span>
                )}
              </Link>
            </li>
          ))}
        </ul>
        <div className="mt-8 rounded-lg border border-gray-200 p-3 dark:border-gray-800">
          <div className="flex items-center gap-2">
            <PlugInIcon className="size-4 text-gray-400" />
            <span className="text-xs font-medium text-gray-600 dark:text-gray-300">
              Kernel telemetry
            </span>
          </div>
          <p className="mt-1 text-[11px] leading-4 text-gray-500 dark:text-gray-400">
            eBPF / Linux audit / process events, normalized and scored by the
            GuardianOS-AI detection pipeline.
          </p>
        </div>
      </nav>
    </aside>
  );
};

export default AppSidebar;
