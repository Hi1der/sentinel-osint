/**
 * SENTINEL OSINT — AI Investigative Analyst Service
 * Synthesizes case evidence, entity topology, and passive reconnaissance telemetry
 * Powered by Google Gemini API (@google/genai) with deterministic heuristic fallback
 */

import { GoogleGenAI } from '@google/genai';
import { InvestigationCase, EvidenceItem, Entity, Relationship } from '../types/osint.ts';

export interface ThreatHypothesis {
  id: string;
  title: string;
  description: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  confidence_score: number; // 0.0 - 1.0
  evidentiary_basis: string[];
}

export interface RiskIndicator {
  type: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  observed_value: string;
}

export interface IntelligenceAssessment {
  case_id: string;
  case_title: string;
  generated_at: string;
  generated_by: 'GEMINI_AI' | 'HEURISTIC_RULE_ENGINE';
  model_used?: string;
  investigative_priority_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  investigative_priority_score: number; // 0 - 100
  methodology_statement: string;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threat_score: number; // 0 - 100
  executive_summary: string;
  infrastructure_assessment: string;
  hypotheses: ThreatHypothesis[];
  risk_indicators: RiskIndicator[];
  recommended_actions: string[];
}

/**
 * Deterministic Heuristic Assessment Engine
 */
export function generateHeuristicAssessment(
  investigationCase: InvestigationCase,
  evidence: EvidenceItem[],
  entities: Entity[],
  relationships: Relationship[]
): IntelligenceAssessment {
  const caseEvidence = evidence.filter(e => e.case_id === investigationCase.id);
  const caseEntities = entities.filter(e => e.case_id === investigationCase.id);
  const caseRelationships = relationships.filter(r => r.case_id === investigationCase.id);

  const riskIndicators: RiskIndicator[] = [];
  const hypotheses: ThreatHypothesis[] = [];
  const recommendedActions: string[] = [];
  let threatScore = 25; // baseline

  // Evaluate domains & subdomains
  const domains = caseEntities.filter(e => e.entity_type === 'DOMAIN');
  const subdomains = caseEntities.filter(e => e.entity_type === 'SUBDOMAIN');
  const ips = caseEntities.filter(e => e.entity_type === 'IP_ADDRESS');
  const asns = caseEntities.filter(e => e.entity_type === 'ASN');
  const certs = caseEntities.filter(e => e.entity_type === 'SSL_CERTIFICATE');

  // Check shared IPs
  const ipResolutionCounts = new Map<string, number>();
  caseRelationships
    .filter(r => r.relationship_type === 'RESOLVES_TO')
    .forEach(r => {
      ipResolutionCounts.set(r.target_entity_id, (ipResolutionCounts.get(r.target_entity_id) || 0) + 1);
    });

  for (const [targetId, count] of ipResolutionCounts.entries()) {
    if (count > 1) {
      const ipEnt = caseEntities.find(e => e.id === targetId);
      const ipVal = ipEnt?.canonical_value || targetId;
      riskIndicators.push({
        type: 'CO_HOSTED_INFRASTRUCTURE',
        severity: 'MEDIUM',
        description: `Multiple distinct in-scope hostnames resolve to the identical IP address (${ipVal}), indicating shared hosting or proxy layer.`,
        observed_value: ipVal
      });
      threatScore += 15;
    }
  }

  // Check certificate anomalies
  for (const cert of certs) {
    if (cert.metadata?.is_expired) {
      riskIndicators.push({
        type: 'EXPIRED_CERTIFICATE',
        severity: 'HIGH',
        description: `Observed TLS certificate (${cert.canonical_value}) has expired, indicating abandoned infrastructure or operational hygiene failure.`,
        observed_value: cert.canonical_value
      });
      threatScore += 20;
    }
  }

  // Check ASN concentration
  if (asns.length === 1 && ips.length > 2) {
    const asn = asns[0];
    hypotheses.push({
      id: 'hyp-asn-01',
      title: 'Monolithic ASN Hosting Footprint',
      description: `All observed hostnames converge into ${asn.display_value}. Infrastructure is consolidated under a single transit provider.`,
      confidence: 'HIGH',
      confidence_score: 0.85,
      evidentiary_basis: caseEvidence.map(e => e.id).slice(0, 3)
    });
  }

  // Subdomain expansion hypothesis
  if (subdomains.length > 0) {
    hypotheses.push({
      id: 'hyp-sub-01',
      title: 'Discovered Peripheral Subdomain Attack Surface',
      description: `Discovered ${subdomains.length} subdomains via Certificate Transparency and passive DNS telemetry. These represent exposed services requiring continuous perimeter monitoring.`,
      confidence: 'MEDIUM',
      confidence_score: 0.75,
      evidentiary_basis: subdomains.flatMap(s => s.source_ids).slice(0, 4)
    });
  }

  // Recommended passive actions
  recommendedActions.push('Perform passive Certificate Transparency cross-referencing on newly discovered subdomains.');
  recommendedActions.push('Monitor RDAP registration expiration dates for potential takeover windows or registrar transfers.');
  recommendedActions.push('Correlate observed IPs against public BGP prefix announcement history for route flapping.');

  // Cap threat score at 100
  threatScore = Math.min(100, Math.max(10, threatScore));
  let threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  if (threatScore >= 80) threatLevel = 'CRITICAL';
  else if (threatScore >= 60) threatLevel = 'HIGH';
  else if (threatScore >= 40) threatLevel = 'MEDIUM';

  const execSummary = `Automated analysis for case "${investigationCase.title}" (${investigationCase.case_number}). ` +
    `Evaluated ${caseEvidence.length} evidence records, ${caseEntities.length} canonical entities (${domains.length} domains, ${subdomains.length} subdomains, ${ips.length} IPs, ${asns.length} ASNs), and ${caseRelationships.length} relationships. ` +
    `Overall posture is assessed as ${threatLevel} (Threat Score: ${threatScore}/100) based on observed infrastructure topology.`;

  const infraAssessment = `Investigation scope contains ${domains.length} primary domain(s) and ${subdomains.length} discovered subdomain(s). ` +
    `DNS resolution ties these assets to ${ips.length} IPv4/IPv6 endpoints across ${asns.length} autonomous system(s). ` +
    (riskIndicators.length > 0 ? `Identified ${riskIndicators.length} operational indicators of concern.` : 'No critical operational anomalies detected in active passive telemetry.');

  const methodologyStmt = 'The Investigative Priority Indicator (0–100) is a weighted triage metric reflecting observed infrastructure exposure, certificate hygiene, and subdomain sprawl. It is intended solely for analyst review prioritization, NOT as an objective probability of threat or proof of malice.';

  return {
    case_id: investigationCase.id,
    case_title: investigationCase.title,
    generated_at: new Date().toISOString(),
    generated_by: 'HEURISTIC_RULE_ENGINE',
    investigative_priority_level: threatLevel,
    investigative_priority_score: threatScore,
    methodology_statement: methodologyStmt,
    threat_level: threatLevel,
    threat_score: threatScore,
    executive_summary: execSummary,
    infrastructure_assessment: infraAssessment,
    hypotheses,
    risk_indicators: riskIndicators,
    recommended_actions: recommendedActions
  };
}

/**
 * Generates an AI-Powered Intelligence Assessment using Gemini API (@google/genai)
 */
export async function generateAiAssessment(
  investigationCase: InvestigationCase,
  evidence: EvidenceItem[],
  entities: Entity[],
  relationships: Relationship[]
): Promise<IntelligenceAssessment> {
  const caseEvidence = evidence.filter(e => e.case_id === investigationCase.id);
  const caseEntities = entities.filter(e => e.case_id === investigationCase.id);
  const caseRelationships = relationships.filter(r => r.case_id === investigationCase.id);

  // If no Gemini API key is present in environment, fall back smoothly to heuristic engine
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return generateHeuristicAssessment(investigationCase, evidence, entities, relationships);
  }

  try {
    const ai = new GoogleGenAI();

    const systemPrompt = `You are SENTINEL AI Analyst, an elite senior cyber threat intelligence architect and OSINT investigator.
Your mission is to perform strictly passive, evidence-backed cyber threat analysis on investigation data.
Analyze the provided investigation case metadata, collected evidence records, normalized entities, and topological graph relationships.
Do NOT hallucinate facts, private records, or external entities not supported by the evidence.
Adhere strictly to authorized passive reconnaissance principles.

You MUST respond strictly with valid, parseable JSON matching the following schema:
{
  "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "threat_score": number (0-100),
  "executive_summary": string,
  "infrastructure_assessment": string,
  "hypotheses": [
    {
      "id": string,
      "title": string,
      "description": string,
      "confidence": "HIGH" | "MEDIUM" | "LOW",
      "confidence_score": number (0.0 to 1.0),
      "evidentiary_basis": string[] (evidence IDs)
    }
  ],
  "risk_indicators": [
    {
      "type": string,
      "severity": "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "description": string,
      "observed_value": string
    }
  ],
  "recommended_actions": string[] (passive OSINT next steps)
}`;

    const contextPayload = {
      case: {
        id: investigationCase.id,
        number: investigationCase.case_number,
        title: investigationCase.title,
        description: investigationCase.description,
        objective: investigationCase.objective,
        priority: investigationCase.priority,
        scope: investigationCase.scope
      },
      evidence_summary: caseEvidence.map(e => ({
        id: e.id,
        collector: e.collector_id,
        target: e.target_identifier,
        value: e.normalized_value,
        timestamp: e.retrieval_timestamp
      })).slice(0, 30),
      entities_summary: caseEntities.map(ent => ({
        id: ent.id,
        type: ent.entity_type,
        value: ent.canonical_value,
        first_seen: ent.first_seen
      })).slice(0, 30),
      relationships_summary: caseRelationships.map(r => ({
        type: r.relationship_type,
        source: r.source_entity_id,
        target: r.target_entity_id,
        evidence: r.evidence_ids
      })).slice(0, 30)
    };

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: [
        { role: 'user', parts: [{ text: `${systemPrompt}\n\nCase Investigation Context:\n${JSON.stringify(contextPayload, null, 2)}` }] }
      ],
      config: {
        responseMimeType: 'application/json'
      }
    });

    const responseText = response.text || '';
    const parsed = JSON.parse(responseText);

    const priorityLevel = parsed.threat_level || parsed.investigative_priority_level || 'MEDIUM';
    const priorityScore = typeof parsed.threat_score === 'number' ? parsed.threat_score : (typeof parsed.investigative_priority_score === 'number' ? parsed.investigative_priority_score : 50);

    return {
      case_id: investigationCase.id,
      case_title: investigationCase.title,
      generated_at: new Date().toISOString(),
      generated_by: 'GEMINI_AI',
      model_used: 'gemini-3.8-flash',
      investigative_priority_level: priorityLevel,
      investigative_priority_score: priorityScore,
      methodology_statement: 'The Investigative Priority Indicator (0–100) is synthesized by Google Gemini 3.8 Flash based on evidence in active case scope. It serves strictly as an analyst triage indicator, NOT an objective culpability verdict.',
      threat_level: priorityLevel,
      threat_score: priorityScore,
      executive_summary: parsed.executive_summary || 'AI synthesis completed.',
      infrastructure_assessment: parsed.infrastructure_assessment || 'Assessment completed.',
      hypotheses: Array.isArray(parsed.hypotheses) ? parsed.hypotheses : [],
      risk_indicators: Array.isArray(parsed.risk_indicators) ? parsed.risk_indicators : [],
      recommended_actions: Array.isArray(parsed.recommended_actions) ? parsed.recommended_actions : []
    };
  } catch (err) {
    console.error('Gemini AI analysis error, falling back to heuristic engine:', err);
    return generateHeuristicAssessment(investigationCase, evidence, entities, relationships);
  }
}
