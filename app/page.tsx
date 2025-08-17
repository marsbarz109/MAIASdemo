"use client";

import React, { useState, useEffect } from 'react';

type Agent = 'MasterMind' | 'DevAssist' | 'CyberGuard' | 'DataFlow';
type Decision = 'approved' | 'blocked' | 'manual_approval';
type Scenario = 'devops' | 'sec_triage' | 'data_publish' | 'it_onboarding';

interface LogEvent {
  id: string;
  ts: string;
  agent: Agent;
  kind: 'info' | 'tool' | 'decision';
  msg: string;
  toolCall?: {
    tool: string;
    params: Record<string, unknown>;
    result: 'ok' | 'warn' | 'error';
    details?: string;
  };
  explanation?: string;
}

interface RunInput {
  scenario: Scenario;
  fields: Record<string, string>;
  demoMode: boolean;
}

interface RunResult {
  timeline: LogEvent[];
  decision: Decision;
  summary: string;
}

const scenarios = [
  { id: 'devops', name: 'DevOps Release Gate' },
  { id: 'sec_triage', name: 'Security Alert Triage' },
  { id: 'data_publish', name: 'Data Pipeline Publish' },
  { id: 'it_onboarding', name: 'IT Onboarding (Helpdesk)' }
];

const sampleInputs: Record<Scenario, Record<string, string>> = {
  devops: {
    title: 'Add dynamic rule evaluation',
    prText: 'routes/promo.ts uses eval() on request.body.rule; logs raw user input; no sanitization.',
    environment: 'prod'
  },
  sec_triage: {
    alertJson: '{"rule":"SuspiciousS3Access","actor":"svc-reporter","resource":"s3://public_s3/backups","severity":"high"}',
    severity: 'high'
  },
  data_publish: {
    datasetName: 'sales_kpis_daily',
    environment: 'prod',
    notes: 'publish monthly board pack'
  },
  it_onboarding: {
    name: 'Alice Nguyen',
    department: 'Finance',
    startDate: '2025-09-01',
    ticketId: 'INC12345'
  }
};

const fieldDefinitions: Record<
  Scenario,
  { name: string; label: string; type: string }[]
> = {
  devops: [
    { name: 'title', label: 'Title', type: 'text' },
    { name: 'prText', label: 'PR/Diff Text', type: 'textarea' },
    { name: 'environment', label: 'Environment', type: 'select' }
  ],
  sec_triage: [
    { name: 'alertJson', label: 'Alert JSON', type: 'textarea' },
    { name: 'severity', label: 'Severity', type: 'select' }
  ],
  data_publish: [
    { name: 'datasetName', label: 'Dataset Name', type: 'text' },
    { name: 'environment', label: 'Environment', type: 'select' },
    { name: 'notes', label: 'Notes', type: 'textarea' }
  ],
  it_onboarding: [
    { name: 'name', label: 'Name', type: 'text' },
    { name: 'department', label: 'Department', type: 'text' },
    { name: 'startDate', label: 'Start Date', type: 'date' },
    { name: 'ticketId', label: 'Ticket ID (optional)', type: 'text' }
  ]
};

const selectOptions: Record<string, string[]> = {
  environment: ['staging', 'prod'],
  severity: ['low', 'med', 'high']
};

const agentInfo: Record<
  Agent,
  { avatar: string; role: string; description: string }
> = {
  MasterMind: {
    avatar: '🧠',
    role: 'Orchestrator',
    description:
      'Coordinates the multi-agent workflow, delegates tasks, and makes final decisions'
  },
  DevAssist: {
    avatar: '💻',
    role: 'Developer Assistant',
    description:
      'Analyzes code, runs security scans, and provides technical insights'
  },
  CyberGuard: {
    avatar: '🛡️',
    role: 'Security Guardian',
    description:
      'Enforces security policies, detects risks, and ensures compliance'
  },
  DataFlow: {
    avatar: '📊',
    role: 'Data Flow Manager',
    description:
      'Validates data pipelines, checks schemas, and ensures data quality'
  }
};

const agentExplanations: Record<Scenario, Record<Agent, string>> = {
  devops: {
    MasterMind:
      'Orchestrating the release process by coordinating code analysis, security checks, and deployment validation',
    DevAssist:
      'Analyzing the pull request for potential security vulnerabilities and code quality issues',
    CyberGuard:
      'Enforcing security policies to prevent unsafe code from being deployed to production',
    DataFlow:
      'Validating that data flows and database migrations are safe for the target environment'
  },
  sec_triage: {
    MasterMind:
      'Coordinating the security alert analysis and determining appropriate response actions',
    CyberGuard:
      'Triaging the alert based on severity, threat intelligence, and organizational policies',
    DevAssist:
      'Providing technical context and runbook recommendations for incident response',
    DataFlow:
      'Not involved in this scenario - security triage focuses on threat analysis'
  },
  data_publish: {
    MasterMind:
      'Managing the data pipeline validation workflow and ensuring compliance requirements',
    DataFlow:
      'Validating data quality, schema consistency, and pipeline readiness for deployment',
    CyberGuard:
      'Checking for sensitive data (PII) and enforcing data privacy policies',
    DevAssist: 'Not involved in this scenario - data validation is handled by specialized agents'
  },
  it_onboarding: {
    MasterMind:
      'Planning and coordinating the employee onboarding process across systems',
    DevAssist:
      'Generating onboarding plans and runbooks based on department requirements',
    CyberGuard:
      'Ensuring proper access controls and compliance with least privilege principles',
    DataFlow:
      'Not involved in this scenario - onboarding focuses on access provisioning'
  }
};

const toolExplanations: Record<string, string> = {
  'workflow.init':
    'Initializes the multi-agent orchestration workflow for the selected scenario',
  'sast.scan':
    'Static Application Security Testing - scans source code for security vulnerabilities',
  'github.lint':
    'Code linting tool that checks for coding standards and potential issues',
  'policy.check': 'Validates actions against organizational security and compliance policies',
  'ticket.create':
    'Creates tickets in issue tracking systems for manual review or follow-up',
  'siem.lookup':
    'Security Information and Event Management - looks up threat intelligence',
  'threatintel.query':
    'Queries threat intelligence databases for known malicious indicators',
  'ticket.update': 'Updates ticket status in issue tracking systems',
  'parser.validate': 'Validates data formats and structures',
  'pii.scan': 'Scans datasets for Personally Identifiable Information (PII)',
  'rbac.validate':
    'Validates Role-Based Access Control permissions and group memberships',
  'access.grant': 'Provisions user access to systems and resources',
  'runbook.fetch': 'Retrieves standard operating procedures for specific processes',
  'slack.invite': 'Sends invitations to collaboration platforms',
  'ci.build': 'Continuous Integration build process that compiles and tests code',
  'db.migrate': 'Database migration tool that applies schema changes',
  'dbt.test': 'Data Build Tool - runs data quality tests and validations',
  'airflow.dag_status': 'Checks the status of data pipeline workflows',
  'schema.registry.diff': 'Compares data schemas to detect inconsistencies',
  'orchestrator.finalize':
    'Finalizes the orchestration process and records the decision',
  'audit.manual_approval':
    'Records manual approval actions for audit trail purposes'
};

const createToolCall = (
  agent: Agent,
  tool: string,
  params: Record<string, unknown>,
  result: 'ok' | 'warn' | 'error',
  details?: string
): LogEvent => ({
  id: `tool-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
  ts: new Date().toISOString(),
  agent: agent,
  kind: 'tool',
  msg: `Executed ${tool}`,
  toolCall: {
    tool,
    params,
    result,
    details
  },
  explanation: toolExplanations[tool] || `Executing ${tool} tool for ${agent}`
});

const simulateAgentReasoning = (
  agent: Agent,
  scenario: string,
  fields: Record<string, string>
): {
  decision?: Decision;
  message: string;
  toolCalls?: LogEvent[];
  explanation: string;
} => {
  const toolCalls: LogEvent[] = [];
  const explanation = agentExplanations[scenario as Scenario][agent] || `Agent ${agent} performing analysis`;

  switch (agent) {
    case 'MasterMind':
      return {
        message: 'Orchestrating multi-agent workflow',
        explanation,
        toolCalls: [
          createToolCall('MasterMind', 'workflow.init', { scenario }, 'ok', 'Workflow initialized')
        ]
      };
    case 'DevAssist':
      if (scenario === 'devops') {
        const prText = fields.prText || '';
        if (prText.includes('eval(') || prText.includes('raw user input')) {
          return {
            message: 'Security risk detected in code',
            explanation,
            toolCalls: [
              createToolCall('DevAssist', 'sast.scan', { file: 'routes/promo.ts' }, 'error', 'Found eval() usage'),
              createToolCall('DevAssist', 'github.lint', { repo: 'project' }, 'warn', 'Security linting failed')
            ]
          };
        }
        return {
          message: 'Code review passed security checks',
          explanation,
          toolCalls: [
            createToolCall('DevAssist', 'sast.scan', { file: 'routes/promo.ts' }, 'ok', 'No security issues found'),
            createToolCall('DevAssist', 'github.lint', { repo: 'project' }, 'ok', 'Code linting passed')
          ]
        };
      }
      if (scenario === 'it_onboarding') {
        return {
          message: 'Generated onboarding plan',
          explanation,
          toolCalls: [
            createToolCall('DevAssist', 'runbook.fetch', { department: fields.department }, 'ok', 'Retrieved onboarding runbook'),
            createToolCall('DevAssist', 'slack.invite', { user: fields.name }, 'ok', 'Prepared Slack invitation')
          ]
        };
      }
      return { message: 'No specific action required', explanation, toolCalls: [] };
    case 'CyberGuard':
      if (scenario === 'devops') {
        const prText = fields.prText || '';
        if (prText.includes('eval(') || prText.includes('raw user input')) {
          return {
            decision: 'manual_approval',
            message: 'Manual approval required due to security policy',
            explanation,
            toolCalls: [
              createToolCall('CyberGuard', 'policy.check', { rule: 'SEC-12' }, 'error', 'Policy violation detected'),
              createToolCall('CyberGuard', 'ticket.create', { type: 'security_review' }, 'ok', 'Created security review ticket')
            ]
          };
        }
        return {
          decision: 'approved',
          message: 'Security checks passed',
          explanation,
          toolCalls: [
            createToolCall('CyberGuard', 'policy.check', { rule: 'SEC-12' }, 'ok', 'Policy compliance verified'),
            createToolCall('CyberGuard', 'scan.complete', {}, 'ok', 'Security scan completed')
          ]
        };
      }
      if (scenario === 'sec_triage') {
        const alertJson = fields.alertJson || '{}';
        const severity = fields.severity || 'low';
        try {
          const alert = JSON.parse(alertJson) as any;
          if (
            severity === 'high' ||
            (alert.resource && (alert.resource as string).includes('public_s3')) ||
            (alert.rule && (alert.rule as string).includes('exfil'))
          ) {
            return {
              decision: 'manual_approval',
              message: 'High severity alert requires manual review',
              explanation,
              toolCalls: [
                createToolCall('CyberGuard', 'siem.lookup', { actor: alert.actor }, 'warn', 'Suspicious activity detected'),
                createToolCall('CyberGuard', 'threatintel.query', { indicator: alert.resource }, 'error', 'Known malicious resource')
              ]
            };
          }
          if (alert.duplicate_id) {
            return {
              decision: 'blocked',
              message: 'Duplicate alert - auto-resolved',
              explanation,
              toolCalls: [
                createToolCall('CyberGuard', 'ticket.update', { status: 'resolved' }, 'ok', 'Marked as duplicate')
              ]
            };
          }
          return {
            decision: 'approved',
            message: 'Low severity alert - auto-approved',
            explanation,
            toolCalls: [
              createToolCall('CyberGuard', 'siem.lookup', { actor: alert.actor }, 'ok', 'No suspicious activity'),
              createToolCall('CyberGuard', 'ticket.update', { status: 'closed' }, 'ok', 'Auto-closed low severity')
            ]
          };
        } catch {
          return {
            decision: 'manual_approval',
            message: 'Invalid alert JSON format',
            explanation,
            toolCalls: [
              createToolCall('CyberGuard', 'parser.validate', { format: 'json' }, 'error', 'Malformed JSON input')
            ]
          };
        }
      }
      if (scenario === 'data_publish') {
        const datasetName = fields.datasetName || '';
        const environment = fields.environment || 'staging';
        if (datasetName.includes('pii') && environment === 'prod') {
          return {
            decision: 'manual_approval',
            message: 'PII data in production requires privacy review',
            explanation,
            toolCalls: [
              createToolCall('CyberGuard', 'pii.scan', { dataset: datasetName }, 'error', 'PII detected in dataset'),
              createToolCall('CyberGuard', 'policy.check', { rule: 'PRIVACY-01' }, 'error', 'Production PII policy violation')
            ]
          };
        }
        return {
          decision: 'approved',
          message: 'Data privacy checks passed',
          explanation,
          toolCalls: [
            createToolCall('CyberGuard', 'pii.scan', { dataset: datasetName }, 'ok', 'No PII detected'),
            createToolCall('CyberGuard', 'policy.check', { rule: 'PRIVACY-01' }, 'ok', 'Privacy policy compliance verified')
          ]
        };
      }
      if (scenario === 'it_onboarding') {
        const department = fields.department || '';
        if (department === 'Finance') {
          return {
            decision: 'manual_approval',
            message: 'Finance department requires SOX compliance review',
            explanation,
            toolCalls: [
              createToolCall('CyberGuard', 'rbac.validate', { department }, 'warn', 'SOX group access required'),
              createToolCall('CyberGuard', 'ticket.create', { type: 'sox_review' }, 'ok', 'Created SOX compliance ticket')
            ]
          };
        }
        return {
          decision: 'approved',
          message: 'RBAC checks passed',
          explanation,
          toolCalls: [
            createToolCall('CyberGuard', 'rbac.validate', { department }, 'ok', 'Least privilege access granted'),
            createToolCall('CyberGuard', 'access.grant', { user: fields.name }, 'ok', 'Standard access provisioned')
          ]
        };
      }
      return { message: 'No specific action required', explanation, toolCalls: [] };
    case 'DataFlow':
      if (scenario === 'devops') {
        const environment = fields.environment || 'staging';
        if (environment === 'prod') {
          return {
            message: 'Production deployment - data flow validation required',
            explanation,
            toolCalls: [
              createToolCall('DataFlow', 'ci.build', { branch: 'main' }, 'ok', 'Build successful'),
              createToolCall('DataFlow', 'db.migrate', { env: environment }, 'warn', 'Schema migration needed')
            ]
          };
        }
        return {
          message: 'Staging deployment - data flow checks passed',
          explanation,
          toolCalls: [
            createToolCall('DataFlow', 'ci.build', { branch: 'feature' }, 'ok', 'Build successful'),
            createToolCall('DataFlow', 'db.migrate', { env: environment }, 'ok', 'Schema up to date')
          ]
        };
      }
      if (scenario === 'data_publish') {
        const datasetName = fields.datasetName || '';
        if (datasetName.includes('sales')) {
          return {
            message: 'Sales data detected - late partition warning',
            explanation,
            toolCalls: [
              createToolCall('DataFlow', 'dbt.test', { model: datasetName }, 'warn', 'Late data partition detected'),
              createToolCall('DataFlow', 'airflow.dag_status', { dag: 'sales_pipeline' }, 'ok', 'Pipeline running normally')
            ]
          };
        }
        return {
          message: 'Data pipeline validation passed',
          explanation,
          toolCalls: [
            createToolCall('DataFlow', 'dbt.test', { model: datasetName }, 'ok', 'Data quality tests passed'),
            createToolCall('DataFlow', 'schema.registry.diff', { dataset: datasetName }, 'ok', 'Schema validation successful')
          ]
        };
      }
      return { message: 'No specific action required', explanation, toolCalls: [] };
    default:
      return { message: 'Agent processing...', explanation: 'Agent performing analysis', toolCalls: [] };
  }
};

const simulateOrchestration = async (input: RunInput): Promise<RunResult> => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const { scenario, fields } = input;
      const timeline: LogEvent[] = [];
      timeline.push({
        id: `init-${Date.now()}`,
        ts: new Date().toISOString(),
        agent: 'MasterMind',
        kind: 'info',
        msg: `Starting orchestration for ${scenario} scenario`,
        explanation: 'Initializing the multi-agent orchestration workflow'
      });

      let decision: Decision = 'approved';
      let summary = '';

      switch (scenario) {
        case 'devops': {
          timeline.push({
            id: `step-1-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'MasterMind',
            kind: 'info',
            msg: 'Analyzing pull request',
            explanation: agentExplanations.devops.MasterMind
          });

          const devAssistResult = simulateAgentReasoning('DevAssist', scenario, fields);
          timeline.push({
            id: `step-2-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'DevAssist',
            kind: 'info',
            msg: devAssistResult.message,
            explanation: devAssistResult.explanation
          });
          if (devAssistResult.toolCalls) timeline.push(...devAssistResult.toolCalls);

          const cyberGuardResult = simulateAgentReasoning('CyberGuard', scenario, fields);
          timeline.push({
            id: `step-3-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'CyberGuard',
            kind: 'info',
            msg: cyberGuardResult.message,
            explanation: cyberGuardResult.explanation
          });
          if (cyberGuardResult.toolCalls) timeline.push(...cyberGuardResult.toolCalls);
          if (cyberGuardResult.decision) decision = cyberGuardResult.decision || 'approved';

          const dataFlowResult = simulateAgentReasoning('DataFlow', scenario, fields);
          timeline.push({
            id: `step-4-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'DataFlow',
            kind: 'info',
            msg: dataFlowResult.message,
            explanation: dataFlowResult.explanation
          });
          if (dataFlowResult.toolCalls) timeline.push(...dataFlowResult.toolCalls);

          timeline.push({
            id: `step-5-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'MasterMind',
            kind: 'info',
            msg: 'Finalizing release decision',
            explanation: 'Making final decision based on all agent analyses'
          });

          const prText = fields.prText || '';
          const environment = fields.environment || 'staging';
          if (prText.includes('eval(') || prText.includes('raw user input')) {
            decision = 'manual_approval';
            summary = 'Security risk detected. Manual approval required before deployment.';
          } else if (cyberGuardResult.decision === 'blocked') {
            decision = 'blocked';
            summary = 'Security policy violation. Release blocked.';
          } else if (environment === 'prod') {
            decision = 'approved';
            summary = 'Production deployment approved with security checks passed.';
          } else {
            decision = 'approved';
            summary = 'Staging deployment approved.';
          }
          break;
        }
        case 'sec_triage': {
          timeline.push({
            id: `step-1-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'MasterMind',
            kind: 'info',
            msg: 'Analyzing security alert',
            explanation: agentExplanations.sec_triage.MasterMind
          });

          const cyberGuardTriageResult = simulateAgentReasoning('CyberGuard', scenario, fields);
          timeline.push({
            id: `step-2-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'CyberGuard',
            kind: 'info',
            msg: cyberGuardTriageResult.message,
            explanation: cyberGuardTriageResult.explanation
          });
          if (cyberGuardTriageResult.toolCalls) timeline.push(...cyberGuardTriageResult.toolCalls);
          if (cyberGuardTriageResult.decision) decision = cyberGuardTriageResult.decision || 'approved';

          const devAssistEnrichmentResult = simulateAgentReasoning('DevAssist', scenario, fields);
          timeline.push({
            id: `step-3-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'DevAssist',
            kind: 'info',
            msg: devAssistEnrichmentResult.message,
            explanation: devAssistEnrichmentResult.explanation
          });
          if (devAssistEnrichmentResult.toolCalls) timeline.push(...devAssistEnrichmentResult.toolCalls);

          timeline.push({
            id: `step-4-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'MasterMind',
            kind: 'info',
            msg: 'Finalizing alert triage',
            explanation: 'Making final decision based on security analysis and recommendations'
          });

          const alertJsonSec = fields.alertJson || '{}';
          const severity = fields.severity || 'low';
          try {
            const alert = JSON.parse(alertJsonSec) as any;
            if (
              severity === 'high' ||
              (alert.resource && (alert.resource as string).includes('public_s3')) ||
              (alert.rule && (alert.rule as string).includes('exfil'))
            ) {
              decision = 'manual_approval';
              summary = 'High severity alert requires manual review.';
            } else if (alert.duplicate_id) {
              decision = 'blocked';
              summary = 'Duplicate alert automatically resolved.';
            } else {
              decision = 'approved';
              summary = 'Low severity alert auto-approved.';
            }
          } catch {
            decision = 'manual_approval';
            summary = 'Invalid alert format requires manual review.';
          }
          break;
        }
        case 'data_publish': {
          timeline.push({
            id: `step-1-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'MasterMind',
            kind: 'info',
            msg: 'Validating data pipeline',
            explanation: agentExplanations.data_publish.MasterMind
          });

          const dataFlowValidationResult = simulateAgentReasoning('DataFlow', scenario, fields);
          timeline.push({
            id: `step-2-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'DataFlow',
            kind: 'info',
            msg: dataFlowValidationResult.message,
            explanation: dataFlowValidationResult.explanation
          });
          if (dataFlowValidationResult.toolCalls) timeline.push(...dataFlowValidationResult.toolCalls);

          const cyberGuardPIIResult = simulateAgentReasoning('CyberGuard', scenario, fields);
          timeline.push({
            id: `step-3-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'CyberGuard',
            kind: 'info',
            msg: cyberGuardPIIResult.message,
            explanation: cyberGuardPIIResult.explanation
          });
          if (cyberGuardPIIResult.toolCalls) timeline.push(...cyberGuardPIIResult.toolCalls);
          if (cyberGuardPIIResult.decision) decision = cyberGuardPIIResult.decision || 'approved';

          timeline.push({
            id: `step-4-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'MasterMind',
            kind: 'info',
            msg: 'Finalizing data publish decision',
            explanation: 'Making final decision based on data quality and security checks'
          });

          const datasetName = fields.datasetName || '';
          const environmentData = fields.environment || 'staging';
          if (datasetName.includes('pii') && environmentData === 'prod') {
            decision = 'manual_approval';
            summary = 'PII data in production requires privacy review.';
          } else if (datasetName.includes('sales')) {
            decision = 'approved';
            summary = 'Sales data published with late partition warning.';
          } else {
            decision = 'approved';
            summary = 'Data pipeline validation passed.';
          }
          break;
        }
        case 'it_onboarding': {
          timeline.push({
            id: `step-1-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'MasterMind',
            kind: 'info',
            msg: 'Creating onboarding plan',
            explanation: agentExplanations.it_onboarding.MasterMind
          });

          const devAssistPlanResult = simulateAgentReasoning('DevAssist', scenario, fields);
          timeline.push({
            id: `step-2-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'DevAssist',
            kind: 'info',
            msg: devAssistPlanResult.message,
            explanation: devAssistPlanResult.explanation
          });
          if (devAssistPlanResult.toolCalls) timeline.push(...devAssistPlanResult.toolCalls);

          const cyberGuardRBACResult = simulateAgentReasoning('CyberGuard', scenario, fields);
          timeline.push({
            id: `step-3-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'CyberGuard',
            kind: 'info',
            msg: cyberGuardRBACResult.message,
            explanation: cyberGuardRBACResult.explanation
          });
          if (cyberGuardRBACResult.toolCalls) timeline.push(...cyberGuardRBACResult.toolCalls);
          if (cyberGuardRBACResult.decision) decision = cyberGuardRBACResult.decision || 'approved';

          timeline.push({
            id: `step-4-${Date.now()}`,
            ts: new Date().toISOString(),
            agent: 'MasterMind',
            kind: 'info',
            msg: 'Finalizing onboarding process',
            explanation: 'Making final decision based on onboarding plan and security checks'
          });

          const department = fields.department || '';
          if (department === 'Finance') {
            decision = 'manual_approval';
            summary = 'Finance department requires SOX compliance review.';
          } else {
            decision = 'approved';
            summary = 'Onboarding plan approved and ready for execution.';
          }
          break;
        }
      }

      timeline.push({
        id: `final-${Date.now()}`,
        ts: new Date().toISOString(),
        agent: 'MasterMind',
        kind: 'decision',
        msg: `Decision: ${decision}`,
        explanation: 'Final orchestration decision based on all agent inputs',
        toolCall: {
          tool: 'orchestrator.finalize',
          params: { decision },
          result: decision === 'approved' ? 'ok' : decision === 'blocked' ? 'error' : 'warn'
        }
      });

      resolve({ timeline, decision, summary });
    }, 300);
  });
};

const simulateManualApproval = (): Promise<RunResult> => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const approvalEvent: LogEvent = {
        id: `approve-${Date.now()}`,
        ts: new Date().toISOString(),
        agent: 'MasterMind',
        kind: 'decision',
        msg: 'Manual approval granted by operator',
        explanation: 'Human operator has overridden the automated decision',
        toolCall: {
          tool: 'audit.manual_approval',
          params: { approver: 'demo_user' },
          result: 'ok',
          details: 'Manual override of previous decision'
        }
      };
      resolve({ timeline: [approvalEvent], decision: 'approved', summary: 'Manual approval granted. Process completed.' });
    }, 200);
  });
};

export default function MAIASDemo() {
  const [selectedScenario, setSelectedScenario] = useState<Scenario>('devops');
  const [formData, setFormData] = useState<Record<string, string>>(sampleInputs.devops);
  const [demoMode, setDemoMode] = useState(true);
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<RunResult | null>(null);
  const [showToolLogs, setShowToolLogs] = useState<Record<string, boolean>>({});
  const [needsApproval, setNeedsApproval] = useState(false);
  const [hoveredItem, setHoveredItem] = useState<{ type: 'agent' | 'tool' | 'event'; id: string } | null>(null);

  useEffect(() => {
    setFormData(sampleInputs[selectedScenario]);
    setResult(null);
    setNeedsApproval(false);
  }, [selectedScenario]);

  const handleInputChange = (name: string, value: string) => {
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const toggleToolLogs = (id: string) => {
    setShowToolLogs((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const runOrchestration = async () => {
    setIsRunning(true);
    setResult(null);
    setNeedsApproval(false);
    try {
      const data: RunResult = await simulateOrchestration({
        scenario: selectedScenario,
        fields: formData,
        demoMode
      });
      setResult(data);
      if (data.decision === 'manual_approval') setNeedsApproval(true);
    } catch (error) {
      console.error('Error running orchestration:', error);
    } finally {
      setIsRunning(false);
    }
  };

  const approveManually = async () => {
    if (!result) return;
    try {
      const data: RunResult = await simulateManualApproval();
      setResult({
        ...result,
        timeline: [...result.timeline, ...data.timeline],
        decision: data.decision,
        summary: data.summary
      });
      setNeedsApproval(false);
    } catch (error) {
      console.error('Error approving:', error);
    }
  };

  const formatTime = (isoString: string) => new Date(isoString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 p-4 md:p-8">
      <div className="max-w-6xl mx-auto">
        <header className="mb-8 text-center">
          <h1 className="text-3xl md:text-4xl font-bold text-gray-800 mb-2">Multi-Agent Orchestration Demo</h1>
          <p className="text-gray-600">MAIAS - Multi-scenario Multi-Agent Intelligent System</p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1 bg-white rounded-xl shadow-lg p-6 h-fit">
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-2">Scenario</label>
              <select
                value={selectedScenario}
                onChange={(e) => setSelectedScenario(e.target.value as Scenario)}
                className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                disabled={isRunning}
              >
                {scenarios.map((scenario) => (
                  <option key={scenario.id} value={scenario.id}>
                    {scenario.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="mb-6">
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium text-gray-700">Mode</label>
                <div className="flex items-center">
                  <span className={`text-sm mr-2 ${demoMode ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>Demo</span>
                  <button
                    onClick={() => setDemoMode(!demoMode)}
                    className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${demoMode ? 'bg-blue-500' : 'bg-gray-300'}`}
                  >
                    <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${demoMode ? 'translate-x-6' : 'translate-x-1'}`} />
                  </button>
                  <span className={`text-sm ml-2 ${!demoMode ? 'text-blue-600 font-medium' : 'text-gray-500'}`}>Live</span>
                </div>
              </div>
              <p className="text-xs text-gray-500 mt-1">
                {demoMode ? 'Simulated deterministic behavior' : 'Requires OPENAI_API_KEY in environment'}
              </p>
            </div>

            <div className="mb-6">
              <h3 className="text-lg font-medium text-gray-800 mb-3">Inputs</h3>
              <div className="space-y-4">
                {fieldDefinitions[selectedScenario].map((field) => (
                  <div key={field.name}>
                    <label className="block text-sm font-medium text-gray-700 mb-1">{field.label}</label>
                    {field.type === 'textarea' ? (
                      <textarea
                        value={formData[field.name] || ''}
                        onChange={(e) => handleInputChange(field.name, e.target.value)}
                        className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        rows={3}
                        disabled={isRunning}
                      />
                    ) : field.type === 'select' ? (
                      <select
                        value={formData[field.name] || ''}
                        onChange={(e) => handleInputChange(field.name, e.target.value)}
                        className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        disabled={isRunning}
                      >
                        <option value="">Select...</option>
                        {selectOptions[field.name]?.map((option) => (
                          <option key={option} value={option}>
                            {option}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type={field.type}
                        value={formData[field.name] || ''}
                        onChange={(e) => handleInputChange(field.name, e.target.value)}
                        className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        disabled={isRunning}
                      />
                    )}
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={runOrchestration}
              disabled={isRunning}
              className={`w-full py-3 px-4 rounded-lg font-medium text-white transition-colors ${isRunning ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700 active:bg-blue-800'}`}
            >
              {isRunning ? 'Running Orchestration...' : 'Run Orchestration'}
            </button>
          </div>

          <div className="lg:col-span-2">
            {result && (
              <div
                className={`rounded-xl shadow-lg p-6 mb-6 transition-all duration-300 ${
                  result.decision === 'approved'
                    ? 'bg-green-50 border border-green-200'
                    : result.decision === 'blocked'
                    ? 'bg-red-50 border border-red-200'
                    : 'bg-yellow-50 border border-yellow-200'
                }`}
              >
                <div className="flex items-start">
                  <div
                    className={`flex-shrink-0 w-12 h-12 rounded-full flex items-center justify-center mr-4 ${
                      result.decision === 'approved'
                        ? 'bg-green-100 text-green-800'
                        : result.decision === 'blocked'
                        ? 'bg-red-100 text-red-800'
                        : 'bg-yellow-100 text-yellow-800'
                    }`}
                  >
                    {result.decision === 'approved' ? '✅' : result.decision === 'blocked' ? '❌' : '⚠️'}
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-gray-800 mb-1">
                      {result.decision === 'approved' ? 'Approved' : result.decision === 'blocked' ? 'Blocked' : 'Manual Approval Required'}
                    </h3>
                    <p className="text-gray-700">{result.summary}</p>
                    {needsApproval && (
                      <button
                        onClick={approveManually}
                        className="mt-4 py-2 px-4 bg-yellow-500 hover:bg-yellow-600 text-white rounded-lg font-medium transition-colors"
                      >
                        Approve Anyway
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}

            <div className="bg-white rounded-xl shadow-lg p-6">
              <h3 className="text-lg font-medium text-gray-800 mb-4">Agent Timeline</h3>
              {result ? (
                <div className="space-y-4">
                  {result.timeline.map((event) => (
                    <div key={event.id} className="border-l-4 border-blue-200 pl-4 py-1 relative">
                      <div className="flex items-start">
                        <div
                          className="flex-shrink-0 w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center mr-3 cursor-help relative"
                          onMouseEnter={() => setHoveredItem({ type: 'agent', id: event.agent })}
                          onMouseLeave={() => hoveredItem?.id === event.agent && setHoveredItem(null)}
                        >
                          <span className="text-lg">{agentInfo[event.agent].avatar}</span>
                          {hoveredItem && hoveredItem.id === event.agent && hoveredItem.type === 'agent' && (
                            <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 -translate-y-2 w-64 bg-gray-800 text-white text-sm rounded-lg p-3 shadow-lg z-10">
                              <div className="font-medium mb-1">{agentInfo[event.agent].role}</div>
                              <p>{agentInfo[event.agent].description}</p>
                              <div className="absolute top-full left-1/2 transform -translate-x-1/2 w-0 h-0 border-l-4 border-r-4 border-t-4 border-l-transparent border-r-transparent border-t-gray-800" />
                            </div>
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-baseline">
                            <span className="font-medium text-gray-800">{event.agent}</span>
                            <span className="text-xs text-gray-500 ml-2">{formatTime(event.ts)}</span>
                          </div>
                          <div
                            className="text-gray-700 mt-1 cursor-help relative inline-block"
                            onMouseEnter={() => setHoveredItem({ type: 'event', id: event.id })}
                            onMouseLeave={() => hoveredItem?.id === event.id && setHoveredItem(null)}
                          >
                            <p>{event.msg}</p>
                            {hoveredItem && hoveredItem.id === event.id && hoveredItem.type === 'event' && event.explanation && (
                              <div className="absolute bottom-full left-0 transform -translate-y-2 w-80 bg-gray-800 text-white text-sm rounded-lg p-3 shadow-lg z-10">
                                <div className="font-medium mb-1">Event Explanation</div>
                                <p>{event.explanation}</p>
                                <div className="absolute top-full left-4 w-0 h-0 border-l-4 border-r-4 border-t-4 border-l-transparent border-r-transparent border-t-gray-800" />
                              </div>
                            )}
                          </div>
                          {event.toolCall && (
                            <div className="mt-2">
                              <button onClick={() => toggleToolLogs(event.id)} className="flex items-center text-sm text-blue-600 hover:text-blue-800">
                                <span>{showToolLogs[event.id] ? '▼' : '▶'}</span>
                                <span className="ml-1">Tool Call Details</span>
                              </button>
                              {showToolLogs[event.id] && (
                                <div className="mt-2 bg-gray-50 rounded-lg p-3 text-sm">
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                    <div>
                                      <p className="font-medium text-gray-700">Tool:</p>
                                      <p
                                        className="text-gray-900 cursor-help relative inline-block"
                                        onMouseEnter={() => setHoveredItem({ type: 'tool', id: event.toolCall!.tool })}
                                        onMouseLeave={() => hoveredItem?.id === event.toolCall!.tool && setHoveredItem(null)}
                                      >
                                        {event.toolCall.tool}
                                        {hoveredItem && hoveredItem.id === event.toolCall!.tool && hoveredItem.type === 'tool' && (
                                          <div className="absolute bottom-full left-0 transform -translate-y-2 w-64 bg-gray-800 text-white text-sm rounded-lg p-3 shadow-lg z-10">
                                            <div className="font-medium mb-1">Tool Explanation</div>
                                            <p>{toolExplanations[event.toolCall!.tool] || `Executing ${event.toolCall!.tool} tool`}</p>
                                            <div className="absolute top-full left-4 w-0 h-0 border-l-4 border-r-4 border-t-4 border-l-transparent border-r-transparent border-t-gray-800" />
                                          </div>
                                        )}
                                      </p>
                                    </div>
                                    <div>
                                      <p className="font-medium text-gray-700">Result:</p>
                                      <p className={`${event.toolCall.result === 'ok' ? 'text-green-600' : event.toolCall.result === 'warn' ? 'text-yellow-600' : 'text-red-600'}`}>
                                        {event.toolCall.result.toUpperCase()}
                                      </p>
                                    </div>
                                  </div>
                                  {event.toolCall.details && (
                                    <div className="mt-2">
                                      <p className="font-medium text-gray-700">Details:</p>
                                      <p className="text-gray-900">{event.toolCall.details}</p>
                                    </div>
                                  )}
                                  <div className="mt-2">
                                    <p className="font-medium text-gray-700">Parameters:</p>
                                    <pre className="bg-gray-100 p-2 rounded text-xs overflow-x-auto">{JSON.stringify(event.toolCall.params, null, 2)}</pre>
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-gray-500">
                  {isRunning ? (
                    <div className="flex flex-col items-center">
                      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mb-4" />
                      <p>Running orchestration...</p>
                    </div>
                  ) : (
                    <p>Run a scenario to see the agent timeline</p>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}


