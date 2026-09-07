export {
  InvalidKeyError,
  InvalidOptionError,
  InvalidRuleError,
  isSanitizerError,
  SanitizationAbortedError,
  SanitizerError,
  UnknownRuleError,
  type SanitizerErrorCode,
} from './core/errors';
export { generateKey } from './core/key';
export { createSanitizer, sanitizeStream, sanitizeText } from './core/sanitizer';
export { mergeReports, type MergeReportsOptions } from './core/mergeReports';
export { fromBlob, fromString, fromWebStream } from './io/sources';
export {
  planLineAlignedRanges,
  type ByteRange,
  type PlanLineRangesOptions,
} from './io/planLineRanges';
export { toCallbackSink, toNullSink, toStringSink, type StringSink } from './io/sinks';
export { defineRule } from './rules/defineRule';
export { builtinRuleIds, builtinRules, getBuiltinRule } from './rules/registry';
export type {
  AbortSignalLike,
  AlwaysRedactOptions,
  BlobLike,
  BuiltinRuleId,
  KeyEncoding,
  LineOptions,
  NeverRedactOptions,
  NeverRedactRuleEntry,
  ReadableStreamLike,
  RedactionMode,
  ReportOptions,
  RuleCounts,
  RuleId,
  RuleInfo,
  RuleSelector,
  Sanitizer,
  SanitizerOptions,
  SanitizeProgress,
  SanitizeReplacement,
  SanitizeReport,
  SanitizeRule,
  SanitizeSegment,
  SanitizeStreamOptions,
  SanitizeTextResult,
  TextSink,
  TextSource,
} from './types';
