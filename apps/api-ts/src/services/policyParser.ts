import { existsSync, readFileSync } from 'fs';
import { extname } from 'path';
import { ParsedPolicy, PolicyRule, ComparisonOp, PolicyCategory, Severity } from '../types';

/**
 * PolicyParser — Parses security policy documents from various formats.
 *
 * Supported input formats:
 * - PDF (.pdf) — extracts text via pdf-parse
 * - DOCX (.docx) — extracts text via mammoth
 * - JSON (.json) — structured rule definitions
 * - YAML (.yaml/.yml) — structured rule definitions
 * - Plain text (.txt) — raw policy text
 */
export class PolicyParser {
  /**
   * Parse a policy file from any supported format.
   */
  async parse(filePath: string): Promise<ParsedPolicy> {
    if (!existsSync(filePath)) {
      throw new Error(`Policy file not found: ${filePath}`);
    }

    const ext = extname(filePath).toLowerCase();

    switch (ext) {
      case '.json':
        return this.parseJson(readFileSync(filePath, 'utf-8'));
      case '.yaml':
      case '.yml':
        return this.parseYaml(readFileSync(filePath, 'utf-8'));
      case '.pdf':
        return this.parsePdf(filePath);
      case '.docx':
      case '.doc':
        return this.parseDocx(filePath);
      case '.txt':
        return this.parseText(readFileSync(filePath, 'utf-8'));
      default:
        throw new Error(`Unsupported policy format: ${ext}`);
    }
  }

  /**
   * Parse structured JSON policy definition.
   */
  private parseJson(content: string): ParsedPolicy {
    const data = JSON.parse(content);
    return this.structuredToPolicy(data, 'json');
  }

  /**
   * Parse YAML policy definition.
   */
  private parseYaml(content: string): ParsedPolicy {
    // Dynamic import since js-yaml may not always be available
    try {
      const yaml = require('js-yaml');
      const data = yaml.load(content);
      return this.structuredToPolicy(data, 'yaml');
    } catch {
      // Fallback: treat as plain text
      return this.parseText(content);
    }
  }

  /**
   * Parse PDF policy document.
   */
  private async parsePdf(filePath: string): Promise<ParsedPolicy> {
    try {
      const pdfParse = require('pdf-parse');
      const dataBuffer = readFileSync(filePath);
      const result = await pdfParse(dataBuffer);

      return {
        policyName: this.extractFilename(filePath),
        sourceFormat: 'pdf',
        rawText: result.text,
        rules: [], // Rules will be extracted by LLM
      };
    } catch (err: any) {
      throw new Error(`Failed to parse PDF: ${err.message}`);
    }
  }

  /**
   * Parse DOCX policy document.
   */
  private async parseDocx(filePath: string): Promise<ParsedPolicy> {
    try {
      const mammoth = require('mammoth');
      const dataBuffer = readFileSync(filePath);
      const result = await mammoth.extractRawText({ buffer: dataBuffer });

      return {
        policyName: this.extractFilename(filePath),
        sourceFormat: 'docx',
        rawText: result.value,
        rules: [], // Rules will be extracted by LLM
      };
    } catch (err: any) {
      throw new Error(`Failed to parse DOCX: ${err.message}`);
    }
  }

  /**
   * Parse plain text policy.
   */
  private parseText(content: string): ParsedPolicy {
    return {
      policyName: 'Imported Policy Text',
      sourceFormat: 'text',
      rawText: content,
      rules: [], // Rules will be extracted by LLM
    };
  }

  /**
   * Convert structured JSON/YAML data to ParsedPolicy.
   */
  private structuredToPolicy(data: any, format: 'json' | 'yaml'): ParsedPolicy {
    const rules: PolicyRule[] = (data.rules || []).map((rule: any, index: number) => ({
      id: rule.id || `R${String(index + 1).padStart(3, '0')}`,
      name: rule.name || `Rule ${index + 1}`,
      description: rule.description || '',
      category: this.validateCategory(rule.category),
      severity: this.validateSeverity(rule.severity),
      standard: rule.standard,
      conditions: (rule.conditions || []).map((cond: any) => ({
        field: cond.field || '',
        operator: this.validateOperator(cond.operator),
        value: cond.value,
      })),
    }));

    return {
      policyName: data.policyName || 'Structured Policy',
      version: data.version,
      effectiveDate: data.effectiveDate,
      framework: data.framework,
      sourceFormat: format,
      rules,
      networkZones: data.networkZones,
      authorizedServers: data.authorizedServers,
    };
  }

  /**
   * Validate structured policy format.
   */
  validateStructured(policy: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!policy) {
      return { valid: false, errors: ['Policy object is required'] };
    }
    if (!policy.rules || !Array.isArray(policy.rules)) {
      return { valid: false, errors: ['Policy must have a "rules" array'] };
    }

    for (let i = 0; i < policy.rules.length; i++) {
      const rule = policy.rules[i];
      if (!rule.name) errors.push(`Rule ${i + 1}: missing "name"`);
      if (!rule.category) errors.push(`Rule ${i + 1}: missing "category"`);
      if (!rule.severity) errors.push(`Rule ${i + 1}: missing "severity"`);
      if (!rule.conditions || !Array.isArray(rule.conditions)) {
        errors.push(`Rule ${i + 1}: missing "conditions" array`);
      } else {
        for (let j = 0; j < rule.conditions.length; j++) {
          if (!rule.conditions[j].field) errors.push(`Rule ${i + 1}, condition ${j + 1}: missing "field"`);
          if (!rule.conditions[j].operator) errors.push(`Rule ${i + 1}, condition ${j + 1}: missing "operator"`);
        }
      }
    }

    return { valid: errors.length === 0, errors };
  }

  // ─── Validation Helpers ─────────────────────────────────────────────────

  private validateCategory(cat: string): PolicyCategory {
    const valid: PolicyCategory[] = [
      'encryption', 'network-segmentation', 'access-control',
      'protocol-compliance', 'authentication', 'logging', 'data-exfiltration',
    ];
    return valid.includes(cat as PolicyCategory) ? (cat as PolicyCategory) : 'access-control';
  }

  private validateSeverity(sev: string): Severity {
    const valid: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    return valid.includes(sev as Severity) ? (sev as Severity) : 'medium';
  }

  private validateOperator(op: string): ComparisonOp {
    const valid: ComparisonOp[] = [
      'equals', 'notEquals', 'greaterThan', 'lessThan',
      'contains', 'notContains', 'in', 'notIn', 'inZone', 'matches',
    ];
    return valid.includes(op as ComparisonOp) ? (op as ComparisonOp) : 'equals';
  }

  private extractFilename(filePath: string): string {
    const parts = filePath.replace(/\\/g, '/').split('/');
    return parts[parts.length - 1] || 'Unknown Policy';
  }
}
