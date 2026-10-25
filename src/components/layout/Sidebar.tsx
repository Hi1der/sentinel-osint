import React from 'react';
import { 
  LayoutDashboard, 
  Briefcase, 
  Search, 
  Globe, 
  Server, 
  Network, 
  FileCheck2, 
  Share2, 
  Archive, 
  Clock, 
  FileText, 
  Radio, 
  Terminal, 
  ShieldCheck, 
  Sliders,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import { ActiveView } from '../../types/osint.ts';

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapsed: () => void;
}

interface NavSection {
  title: string;
  items: {
    id: ActiveView;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string;
  }[];
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggleCollapsed }) => {
  const { activeView, setActiveView, stats } = useCase();

  const sections: NavSection[] = [
    {
      title: 'OPERATIONS',
      items: [
        { id: 'overview', label: 'Overview', icon: LayoutDashboard },
        { id: 'investigations', label: 'Investigations', icon: Briefcase, badge: stats?.active_cases?.toString() },
        { id: 'search', label: 'Global Search', icon: Search },
      ],
    },
    {
      title: 'PASSIVE RECON',
      items: [
        { id: 'domain', label: 'Domain Intel', icon: Globe },
        { id: 'ip-asn', label: 'IP & ASN', icon: Server },
        { id: 'dns', label: 'DNS Explorer', icon: Network },
        { id: 'certificates', label: 'Certificates', icon: FileCheck2 },
      ],
    },
    {
      title: 'CORRELATION',
      items: [
        { id: 'graph', label: 'Entity Graph', icon: Share2, badge: stats?.total_entities?.toString() },
        { id: 'evidence', label: 'Evidence Vault', icon: Archive, badge: stats?.total_evidence?.toString() },
        { id: 'timeline', label: 'Timeline', icon: Clock },
        { id: 'reports', label: 'Reports & Export', icon: FileText },
      ],
    },
    {
      title: 'GOVERNANCE',
      items: [
        { id: 'sources', label: 'Data Sources', icon: Radio },
        { id: 'jobs', label: 'Job Monitor', icon: Terminal, badge: stats?.running_jobs ? `${stats.running_jobs} run` : undefined },
        { id: 'audit', label: 'Audit Log', icon: ShieldCheck, badge: 'SHA-256' },
        { id: 'settings', label: 'Settings & Auth', icon: Sliders },
      ],
    },
  ];

  return (
    <aside
      className={`h-[calc(100vh-3.5rem)] bg-[#0B0F19] border-r border-slate-800 transition-all duration-200 flex flex-col shrink-0 z-20 ${
        collapsed ? 'w-14' : 'w-56'
      }`}
    >
      <div className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
        {sections.map((section) => (
          <div key={section.title} className="space-y-1">
            {!collapsed && (
              <div className="px-2 text-[10px] font-mono tracking-wider text-slate-500 uppercase">
                {section.title}
              </div>
            )}
            {section.items.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveView(item.id)}
                  title={collapsed ? item.label : undefined}
                  className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded text-xs transition-colors ${
                    isActive
                      ? 'bg-cyan-950/70 text-cyan-300 font-medium border border-cyan-800/80 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  {!collapsed && (
                    <span className="truncate text-left flex-1">{item.label}</span>
                  )}
                  {!collapsed && item.badge && (
                    <span className="text-[11px] font-mono text-slate-500 tabular-nums">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </div>

      {/* Collapse / Expand Toggle */}
      <div className="p-2 border-t border-slate-800 flex items-center justify-between">
        {!collapsed && (
          <div className="text-[10px] font-mono text-slate-500 truncate">
            v1.0.0 · SHA-256 Validated
          </div>
        )}
        <button
          onClick={onToggleCollapsed}
          className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-900 transition-colors ml-auto"
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>
    </aside>
  );
};
