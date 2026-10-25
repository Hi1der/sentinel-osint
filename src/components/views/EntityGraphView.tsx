import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core, EventObject } from 'cytoscape';
import { 
  Share2, 
  ZoomIn, 
  ZoomOut, 
  Maximize2, 
  RotateCcw, 
  Filter, 
  Download, 
  Info, 
  Layers, 
  CheckCircle2,
  Calendar,
  Sparkles,
  ExternalLink,
  ShieldAlert,
  Loader2
} from 'lucide-react';
import { useCase } from '../../context/CaseContext.tsx';
import * as api from '../../services/api.ts';
import { Entity, Relationship, EntityType, EvidenceItem } from '../../types/osint.ts';

export const EntityGraphView: React.FC = () => {
  const { 
    activeCase, 
    openEntityInInspector, 
    openEvidenceInInspector,
    showNotification,
    refreshStats 
  } = useCase();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const [entities, setEntities] = useState<Entity[]>([]);
  const [relationships, setRelationships] = useState<Relationship[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [selectedNodeData, setSelectedNodeData] = useState<Entity | null>(null);
  const [selectedEdgeData, setSelectedEdgeData] = useState<Relationship | null>(null);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [filterEdgeType, setFilterEdgeType] = useState<string>('ALL');
  const [minConfidence, setMinConfidence] = useState<number>(0.0);
  const [edgeMode, setEdgeMode] = useState<'ALL' | 'FACTS' | 'HYPOTHESIS'>('ALL');
  const [loading, setLoading] = useState(true);
  const [correlating, setCorrelating] = useState(false);

  // Load graph data
  useEffect(() => {
    async function loadData() {
      try {
        const [entData, relData, evData] = await Promise.all([
          api.fetchEntities(activeCase ? activeCase.id : undefined),
          api.fetchRelationships(activeCase ? activeCase.id : undefined),
          api.fetchEvidence(activeCase ? activeCase.id : undefined),
        ]);
        setEntities(entData);
        setRelationships(relData);
        setEvidenceList(evData);
      } catch (err) {
        console.error('Failed to load graph data', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [activeCase]);

  const handleTriggerCorrelation = async () => {
    if (!activeCase) return;
    setCorrelating(true);
    try {
      const res = await api.triggerCorrelation(activeCase.id);
      const [entData, relData, evData] = await Promise.all([
        api.fetchEntities(activeCase.id),
        api.fetchRelationships(activeCase.id),
        api.fetchEvidence(activeCase.id),
      ]);
      setEntities(entData);
      setRelationships(relData);
      setEvidenceList(evData);
      await refreshStats();
      showNotification(
        'success',
        `Correlation completed: ${res.new_entities_count} new entities, ${res.new_relationships_count} new relationships formed.`
      );
    } catch (err: any) {
      showNotification('error', `Correlation failed: ${err.message}`);
    } finally {
      setCorrelating(false);
    }
  };

  // Initialize Cytoscape
  useEffect(() => {
    if (!containerRef.current || entities.length === 0) return;

    // Filter nodes and edges based on state
    const filteredNodes = entities.filter((e) => {
      if (filterType !== 'ALL' && e.entity_type !== filterType) return false;
      if (e.confidence_score < minConfidence) return false;
      return true;
    });

    const activeNodeIds = new Set(filteredNodes.map((n) => n.id));

    const filteredEdges = relationships.filter((r) => {
      if (!activeNodeIds.has(r.source_entity_id) || !activeNodeIds.has(r.target_entity_id)) return false;
      if (filterEdgeType !== 'ALL' && r.relationship_type !== filterEdgeType) return false;
      if (edgeMode === 'FACTS' && r.is_hypothesis) return false;
      if (edgeMode === 'HYPOTHESIS' && !r.is_hypothesis) return false;
      if (r.confidence_score < minConfidence) return false;
      return true;
    });

    const elements = [
      ...filteredNodes.map((e) => {
        let nodeColor = '#06B6D4'; // Cyan default
        if (e.entity_type === 'DOMAIN') nodeColor = '#3B82F6'; // Blue
        if (e.entity_type === 'SUBDOMAIN') nodeColor = '#0EA5E9'; // Sky Blue
        if (e.entity_type === 'IP_ADDRESS') nodeColor = '#10B981'; // Emerald
        if (e.entity_type === 'ASN') nodeColor = '#A855F7'; // Purple
        if (e.entity_type === 'SSL_CERTIFICATE') nodeColor = '#F59E0B'; // Amber
        if (e.entity_type === 'ORGANIZATION') nodeColor = '#6366F1'; // Indigo
        if (e.entity_type === 'PERSON') nodeColor = '#EC4899'; // Pink
        if (e.entity_type === 'EMAIL') nodeColor = '#14B8A6'; // Teal

        return {
          data: {
            id: e.id,
            label: e.display_value.length > 24 ? e.display_value.slice(0, 22) + '…' : e.display_value,
            entityType: e.entity_type,
            rawEntity: e,
            color: nodeColor,
          },
        };
      }),
      ...filteredEdges.map((r) => ({
        data: {
          id: r.id,
          source: r.source_entity_id,
          target: r.target_entity_id,
          label: r.relationship_type.replace(/_/g, ' '),
          rawRelationship: r,
          isHypothesis: r.is_hypothesis,
        },
      })),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            label: 'data(label)',
            color: '#F1F5F9',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '10px',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-background-color': '#0B0F19',
            'text-background-opacity': 0.85,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            width: 28,
            height: 28,
            'border-width': 2,
            'border-color': '#1E293B',
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#38BDF8',
            'border-width': 4,
            'border-opacity': 1,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.5,
            'line-color': '#334155',
            'target-arrow-color': '#64748B',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': '8px',
            color: '#94A3B8',
            'font-family': 'Public Sans, sans-serif',
            'text-rotation': 'autorotate',
            'text-background-color': '#0F172A',
            'text-background-opacity': 0.8,
            'text-background-padding': '1px',
            'line-style': 'solid',
          },
        },
        {
          selector: 'edge[?isHypothesis]',
          style: {
            'line-style': 'dashed',
            'line-color': '#F59E0B',
            'target-arrow-color': '#F59E0B',
          },
        },
        {
          selector: 'edge:selected',
          style: {
            width: 2.5,
            'line-color': '#06B6D4',
            'target-arrow-color': '#06B6D4',
            color: '#38BDF8',
          },
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 500,
        nodeOverlap: 20,
        componentSpacing: 100,
        nodeRepulsion: () => 450000,
        edgeElasticity: () => 100,
        nestingFactor: 5,
        gravity: 80,
        numIter: 1000,
        initialTemp: 200,
        coolingFactor: 0.95,
        minTemp: 1.0,
      },
    });

    cy.on('tap', 'node', (evt: EventObject) => {
      const node = evt.target;
      const raw = node.data('rawEntity') as Entity;
      setSelectedNodeData(raw);
      setSelectedEdgeData(null);
    });

    cy.on('tap', 'edge', (evt: EventObject) => {
      const edge = evt.target;
      const raw = edge.data('rawRelationship') as Relationship;
      setSelectedEdgeData(raw);
      setSelectedNodeData(null);
    });

    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        setSelectedNodeData(null);
        setSelectedEdgeData(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [entities, relationships, filterType, filterEdgeType, edgeMode, minConfidence]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 40);
  const handleReset = () => cyRef.current?.reset();

  const handleExportGraphJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify({ entities, relationships }, null, 2));
    const dlAnchorElem = document.createElement('a');
    dlAnchorElem.setAttribute('href', dataStr);
    dlAnchorElem.setAttribute('download', `sentinel_graph_${activeCase?.case_number || 'export'}.json`);
    dlAnchorElem.click();
  };

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)] relative bg-[#070A12] select-none">
      {/* Top Graph Controls Bar */}
      <div className="h-12 bg-slate-900/90 border-b border-slate-800 px-4 flex items-center justify-between gap-4 z-10 shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Share2 className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-100 text-xs font-sans">
              Temporal Infrastructure Graph
            </span>
          </div>

          <div className="hidden md:flex items-center gap-1.5 text-xs text-slate-400 border-l border-slate-800 pl-3">
            <span>Nodes: <strong className="text-cyan-300 font-mono">{entities.length}</strong></span>
            <span className="text-slate-600">·</span>
            <span>Edges: <strong className="text-blue-300 font-mono">{relationships.length}</strong></span>
          </div>
        </div>

        {/* Filter Controls & Actions */}
        <div className="flex items-center gap-3 text-xs">
          {/* Correlate Evidence Button */}
          <button
            onClick={handleTriggerCorrelation}
            disabled={correlating || !activeCase}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-cyan-950/70 hover:bg-cyan-900/90 border border-cyan-800 text-cyan-300 rounded font-mono text-[11px] transition-colors disabled:opacity-50 cursor-pointer"
            title="Execute evidence-backed correlation across all stored evidence for active case"
          >
            {correlating ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
            ) : (
              <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            )}
            <span>{correlating ? 'Correlating…' : 'Correlate Evidence'}</span>
          </button>

          {/* Entity Type Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px] font-mono">Type:</span>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">ALL TYPES</option>
              <option value="DOMAIN">DOMAIN</option>
              <option value="SUBDOMAIN">SUBDOMAIN</option>
              <option value="IP_ADDRESS">IP ADDRESS</option>
              <option value="ASN">ASN</option>
              <option value="SSL_CERTIFICATE">CERTIFICATE</option>
              <option value="ORGANIZATION">ORGANIZATION</option>
              <option value="PERSON">PERSON</option>
              <option value="EMAIL">EMAIL</option>
            </select>
          </div>

          {/* Edge Mode Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px] font-mono">Edges:</span>
            <select
              value={edgeMode}
              onChange={(e) => setEdgeMode(e.target.value as any)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">ALL LINKS</option>
              <option value="FACTS">OBSERVED FACTS ONLY</option>
              <option value="HYPOTHESIS">HYPOTHESES ONLY</option>
            </select>
          </div>

          {/* Canvas Actions */}
          <div className="flex items-center gap-1 border-l border-slate-800 pl-2">
            <button
              onClick={handleZoomIn}
              className="p-1.5 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              title="Zoom In"
            >
              <ZoomIn className="w-4 h-4" />
            </button>
            <button
              onClick={handleZoomOut}
              className="p-1.5 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              title="Zoom Out"
            >
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              onClick={handleFit}
              className="p-1.5 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              title="Fit to Screen"
            >
              <Maximize2 className="w-4 h-4" />
            </button>
            <button
              onClick={handleReset}
              className="p-1.5 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              title="Reset View"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
            <button
              onClick={handleExportGraphJSON}
              className="p-1.5 rounded text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
              title="Export Graph JSON"
            >
              <Download className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas Viewport */}
      <div className="flex-1 relative overflow-hidden">
        {entities.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 space-y-2">
            <Share2 className="w-10 h-10 text-slate-700 animate-pulse" />
            <p className="text-xs font-mono">No correlated entities in active case.</p>
            {activeCase && (
              <button
                onClick={handleTriggerCorrelation}
                disabled={correlating}
                className="mt-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-400 rounded text-xs font-mono cursor-pointer"
              >
                Run Correlation on Case Evidence
              </button>
            )}
          </div>
        ) : (
          <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
        )}

        {/* Selected Entity Card floating overlay */}
        {selectedNodeData && (
          <div className="absolute bottom-4 left-4 max-w-sm w-full bg-slate-900/95 border border-cyan-700/80 rounded-lg p-3.5 shadow-2xl z-20 space-y-2 text-xs backdrop-blur-xs">
            <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
              <span>{selectedNodeData.entity_type}</span>
              <span className="text-cyan-400 font-bold">
                {Math.round(selectedNodeData.confidence_score * 100)}% Confidence
              </span>
            </div>
            <div className="font-mono text-sm font-semibold text-slate-100 break-all">
              {selectedNodeData.canonical_value}
            </div>
            <div className="flex items-center justify-between pt-1 border-t border-slate-800 text-[11px] font-mono text-slate-400">
              <span>First Seen: {new Date(selectedNodeData.first_seen).toLocaleDateString()}</span>
              <button
                onClick={() => openEntityInInspector(selectedNodeData)}
                className="text-cyan-400 hover:underline text-xs flex items-center gap-1 cursor-pointer"
              >
                Inspect Entity →
              </button>
            </div>
          </div>
        )}

        {/* Selected Edge Card floating overlay */}
        {selectedEdgeData && (
          <div className="absolute bottom-4 left-4 max-w-sm w-full bg-slate-900/95 border border-blue-700/80 rounded-lg p-3.5 shadow-2xl z-20 space-y-2.5 text-xs backdrop-blur-xs">
            <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
              <span>Relationship Edge</span>
              <span className={selectedEdgeData.is_hypothesis ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold'}>
                {selectedEdgeData.is_hypothesis ? 'HYPOTHESIS' : 'OBSERVED FACT'}
              </span>
            </div>
            <div className="font-mono text-xs font-semibold text-slate-200">
              {selectedEdgeData.relationship_type.replace(/_/g, ' ')}
            </div>
            {selectedEdgeData.scoring_explanation && (
              <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                {selectedEdgeData.scoring_explanation}
              </p>
            )}

            {/* Clickable Supporting Evidence Tags */}
            <div className="pt-2 border-t border-slate-800 space-y-1.5">
              <div className="text-[10px] font-mono text-slate-400 uppercase">Supporting Evidence Provenance:</div>
              <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
                {selectedEdgeData.evidence_ids.map((evId) => {
                  const evItem = evidenceList.find((e) => e.id === evId);
                  return (
                    <button
                      key={evId}
                      onClick={() => {
                        if (evItem) {
                          openEvidenceInInspector(evItem);
                        } else {
                          api.fetchEvidence(activeCase?.id).then((list) => {
                            const found = list.find((e) => e.id === evId);
                            if (found) openEvidenceInInspector(found);
                          });
                        }
                      }}
                      className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-cyan-500 text-cyan-300 font-mono text-[10px] flex items-center gap-1 transition-colors cursor-pointer"
                      title="Inspect raw evidence payload in Contextual Inspector"
                    >
                      <ExternalLink className="w-3 h-3 text-cyan-400" />
                      <span>{evId.length > 20 ? evId.slice(0, 18) + '…' : evId}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="absolute top-4 right-4 bg-slate-900/90 border border-slate-800 rounded p-2.5 shadow-xl text-[10px] font-mono space-y-1.5 z-10 backdrop-blur-xs">
          <div className="text-slate-400 uppercase tracking-wider text-[9px] mb-1">Entity Legend</div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-blue-500" />
            <span className="text-slate-300">Domain</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <span className="text-slate-300">Subdomain</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <span className="text-slate-300">IP Address</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-purple-500" />
            <span className="text-slate-300">ASN Entity</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
            <span className="text-slate-300">SSL Certificate</span>
          </div>
        </div>
      </div>
    </div>
  );
};
