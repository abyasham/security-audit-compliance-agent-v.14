"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.tsharkRunner = void 0;
const tsharkRunner_1 = require("./tsharkRunner");
// Shared singleton instance used across routes to keep tshark detection state
// and avoid circular imports through index.ts.
exports.tsharkRunner = new tsharkRunner_1.TsharkRunner();
//# sourceMappingURL=sharedTshark.js.map