import { ParsedPolicy } from '../types';
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
export declare class PolicyParser {
    /**
     * Parse a policy file from any supported format.
     */
    parse(filePath: string): Promise<ParsedPolicy>;
    /**
     * Parse structured JSON policy definition.
     */
    private parseJson;
    /**
     * Parse YAML policy definition.
     */
    private parseYaml;
    /**
     * Parse PDF policy document.
     */
    private parsePdf;
    /**
     * Parse DOCX policy document.
     */
    private parseDocx;
    /**
     * Parse plain text policy.
     */
    private parseText;
    /**
     * Convert structured JSON/YAML data to ParsedPolicy.
     */
    private structuredToPolicy;
    /**
     * Validate structured policy format.
     */
    validateStructured(policy: any): {
        valid: boolean;
        errors: string[];
    };
    private validateCategory;
    private validateSeverity;
    private validateOperator;
    private extractFilename;
}
//# sourceMappingURL=policyParser.d.ts.map