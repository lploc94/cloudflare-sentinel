/**
 * Handler exports
 */

export type { IActionHandler } from './types';

export { LogHandler, type LogHandlerOptions } from './log.handler';
export { NotifyHandler, type NotifyHandlerOptions } from './notify.handler';
export { BlocklistHandler, type BlocklistHandlerOptions } from './blocklist.handler';
export { ReputationHandler, type ReputationHandlerOptions } from './reputation.handler';

// TODO: EscalateHandler - Intended for async AI pipeline integration
// When ESCALATE action is triggered, should fire async AI analysis pipeline
// See: docs/ai-pipeline-design.md (to be created)
