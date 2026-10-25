import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { 
  InvestigationCase, 
  ActiveView, 
  Entity, 
  EvidenceItem 
} from '../types/osint.ts';
import * as api from '../services/api.ts';

interface NotificationState {
  type: 'success' | 'error' | 'info';
  message: string;
}

interface CaseContextType {
  cases: InvestigationCase[];
  activeCase: InvestigationCase | null;
  setActiveCase: (c: InvestigationCase | null) => void;
  activeView: ActiveView;
  setActiveView: (v: ActiveView) => void;
  selectedEntity: Entity | null;
  setSelectedEntity: (e: Entity | null) => void;
  selectedEvidence: EvidenceItem | null;
  setSelectedEvidence: (ev: EvidenceItem | null) => void;
  isInspectorOpen: boolean;
  setIsInspectorOpen: (open: boolean) => void;
  isQuickScanOpen: boolean;
  setIsQuickScanOpen: (open: boolean) => void;
  isNewCaseOpen: boolean;
  setIsNewCaseOpen: (open: boolean) => void;
  quickScanPrefill: { target: string; targetType: string; collectors?: string[] } | null;
  openQuickScan: (prefill?: { target: string; targetType: string; collectors?: string[] }) => void;
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  stats: any;
  loading: boolean;
  notification: NotificationState | null;
  showNotification: (type: 'success' | 'error' | 'info', message: string) => void;
  refreshCases: () => Promise<void>;
  refreshStats: () => Promise<void>;
  openEntityInInspector: (e: Entity) => void;
  openEvidenceInInspector: (ev: EvidenceItem) => void;
}

const CaseContext = createContext<CaseContextType | undefined>(undefined);

export function CaseProvider({ children }: { children: ReactNode }) {
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [activeCase, setActiveCase] = useState<InvestigationCase | null>(null);
  const [activeView, setActiveView] = useState<ActiveView>('overview');
  const [selectedEntity, setSelectedEntity] = useState<Entity | null>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceItem | null>(null);
  const [isInspectorOpen, setIsInspectorOpen] = useState(false);
  const [isQuickScanOpen, setIsQuickScanOpen] = useState(false);
  const [isNewCaseOpen, setIsNewCaseOpen] = useState(false);
  const [quickScanPrefill, setQuickScanPrefill] = useState<{ target: string; targetType: string; collectors?: string[] } | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [notification, setNotification] = useState<NotificationState | null>(null);

  const openQuickScan = (prefill?: { target: string; targetType: string; collectors?: string[] }) => {
    if (prefill) {
      setQuickScanPrefill(prefill);
    } else {
      setQuickScanPrefill(null);
    }
    setIsQuickScanOpen(true);
  };

  const showNotification = (type: 'success' | 'error' | 'info', message: string) => {
    setNotification({ type, message });
    setTimeout(() => {
      setNotification((curr) => (curr?.message === message ? null : curr));
    }, 4500);
  };

  const refreshCases = async () => {
    try {
      const data = await api.fetchCases();
      setCases(data);
      if (data.length > 0 && !activeCase) {
        // Default to first active case or first case
        const firstActive = data.find(c => c.status === 'ACTIVE') || data[0];
        setActiveCase(firstActive);
      } else if (activeCase) {
        // Keep activeCase in sync
        const current = data.find(c => c.id === activeCase.id);
        if (current) setActiveCase(current);
      }
    } catch (err: any) {
      showNotification('error', `Failed to load cases: ${err.message}`);
    }
  };

  const refreshStats = async () => {
    try {
      const data = await api.fetchStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load stats', err);
    }
  };

  useEffect(() => {
    async function init() {
      setLoading(true);
      await Promise.all([refreshCases(), refreshStats()]);
      setLoading(false);
    }
    init();
  }, []);

  const openEntityInInspector = (e: Entity) => {
    setSelectedEntity(e);
    setSelectedEvidence(null);
    setIsInspectorOpen(true);
  };

  const openEvidenceInInspector = (ev: EvidenceItem) => {
    setSelectedEvidence(ev);
    setSelectedEntity(null);
    setIsInspectorOpen(true);
  };

  return (
    <CaseContext.Provider
      value={{
        cases,
        activeCase,
        setActiveCase,
        activeView,
        setActiveView,
        selectedEntity,
        setSelectedEntity,
        selectedEvidence,
        setSelectedEvidence,
        isInspectorOpen,
        setIsInspectorOpen,
        isQuickScanOpen,
        setIsQuickScanOpen,
        isNewCaseOpen,
        setIsNewCaseOpen,
        quickScanPrefill,
        openQuickScan,
        searchQuery,
        setSearchQuery,
        stats,
        loading,
        notification,
        showNotification,
        refreshCases,
        refreshStats,
        openEntityInInspector,
        openEvidenceInInspector,
      }}
    >
      {children}
    </CaseContext.Provider>
  );
}

export function useCase() {
  const context = useContext(CaseContext);
  if (!context) {
    throw new Error('useCase must be used within a CaseProvider');
  }
  return context;
}
