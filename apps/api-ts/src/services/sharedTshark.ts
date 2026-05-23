import { TsharkRunner } from './tsharkRunner';

// Shared singleton instance used across routes to keep tshark detection state
// and avoid circular imports through index.ts.
export const tsharkRunner = new TsharkRunner();
