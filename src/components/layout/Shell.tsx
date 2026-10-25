import React, { useState } from 'react';
import { useCase } from '../../context/CaseContext.tsx';
import { TopBar } from './TopBar.tsx';
import { Sidebar } from './Sidebar.tsx';
import { ContextualInspector } from './ContextualInspector.tsx';
import { NewCaseModal } from '../modals/NewCaseModal.tsx';
import { QuickScanModal } from '../modals/QuickScanModal.tsx';

// Views
import { OverviewView } from '../views/OverviewView.tsx';
import { InvestigationsView } from '../views/InvestigationsView.tsx';
import { EvidenceVaultView } from '../views/EvidenceVaultView.tsx';
import { JobMonitorView } from '../views/JobMonitorView.tsx';
import { EntityGraphView } from '../views/EntityGraphView.tsx';
import { ReportsView } from '../views/ReportsView.tsx';
import { AuditLogView } from '../views/AuditLogView.tsx';
import { DataSourcesView } from '../views/DataSourcesView.tsx';
import { SettingsView } from '../views/SettingsView.tsx';
import { DomainIntelView } from '../views/DomainIntelView.tsx';
import { DnsExplorerView } from '../views/DnsExplorerView.tsx';
import { IpAsnView } from '../views/IpAsnView.tsx';
import { CertificateIntelView } from '../views/CertificateIntelView.tsx';
import { TimelineView } from '../views/TimelineView.tsx';
import { GlobalSearchView } from '../views/GlobalSearchView.tsx';

import { CheckCircle2, AlertTriangle, Info, X } from 'lucide-react';

export const Shell: React.FC = () => {
  const { 
    activeView, 
    notification, 
    isNewCaseOpen, 
    setIsNewCaseOpen, 
    isQuickScanOpen, 
    setIsQuickScanOpen,
    openQuickScan
  } = useCase();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const renderActiveView = () => {
    switch (activeView) {
      case 'overview':
        return <OverviewView onOpenNewCaseModal={() => setIsNewCaseOpen(true)} onOpenQuickScanModal={() => setIsQuickScanOpen(true)} />;
      case 'investigations':
        return <InvestigationsView onOpenNewCaseModal={() => setIsNewCaseOpen(true)} />;
      case 'evidence':
        return <EvidenceVaultView />;
      case 'jobs':
        return <JobMonitorView onOpenQuickScanModal={() => setIsQuickScanOpen(true)} />;
      case 'graph':
        return <EntityGraphView />;
      case 'reports':
        return <ReportsView />;
      case 'audit':
        return <AuditLogView />;
      case 'sources':
        return <DataSourcesView />;
      case 'settings':
        return <SettingsView />;
      case 'domain':
        return <DomainIntelView />;
      case 'dns':
        return <DnsExplorerView />;
      case 'ip-asn':
        return <IpAsnView />;
      case 'certificates':
        return <CertificateIntelView />;
      case 'timeline':
        return <TimelineView />;
      case 'search':
        return <GlobalSearchView />;
      default:
        return <OverviewView onOpenNewCaseModal={() => setIsNewCaseOpen(true)} onOpenQuickScanModal={() => setIsQuickScanOpen(true)} />;
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-100 flex flex-col font-sans">
      {/* Top Command Bar */}
      <TopBar 
        onOpenNewCaseModal={() => setIsNewCaseOpen(true)} 
        onOpenQuickScanModal={() => setIsQuickScanOpen(true)} 
      />

      {/* Main Workspace Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Persistent Collapsible Sidebar */}
        <Sidebar 
          collapsed={sidebarCollapsed} 
          onToggleCollapsed={() => setSidebarCollapsed(!sidebarCollapsed)} 
        />

        {/* Center Viewport */}
        <main className="flex-1 overflow-y-auto bg-[#070A12] relative">
          {renderActiveView()}
        </main>

        {/* Right-Hand Contextual Inspector */}
        <ContextualInspector />
      </div>

      {/* Modals */}
      <NewCaseModal 
        isOpen={isNewCaseOpen} 
        onClose={() => setIsNewCaseOpen(false)} 
      />
      <QuickScanModal 
        isOpen={isQuickScanOpen} 
        onClose={() => setIsQuickScanOpen(false)} 
      />

      {/* Global Toast Notification */}
      {notification && (
        <div className="fixed bottom-4 right-4 z-50 max-w-md bg-slate-900 border border-slate-700 rounded-lg shadow-2xl p-3 flex items-start gap-2.5 text-xs animate-in slide-in-from-bottom-3 duration-200">
          {notification.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />}
          {notification.type === 'error' && <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />}
          {notification.type === 'info' && <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />}
          <div className="flex-1 text-slate-200 leading-snug">{notification.message}</div>
        </div>
      )}
    </div>
  );
};
