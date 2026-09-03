import MySources
import MySinks
import MySummaries
/**
 * Provides a taint-tracking configuration for "Clear-text logging of sensitive information".
 *
 * Note, for performance reasons: only import this file if
 * `CleartextLogging::Configuration` is needed, otherwise
 * `CleartextLoggingCustomizations` should be imported instead.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.dataflow.new.SensitiveDataSources
import CleartextLoggingCustomizations::CleartextLogging

/**
 * DEPRECATED: Use `CleartextLoggingFlow` module instead.
 *
 * A taint-tracking configuration for detecting "Clear-text logging of sensitive information".
 */
deprecated class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "CleartextLogging" }

  override predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink) }

  override predicate isSanitizer(DataFlow::Node node) {
    super.isSanitizer(node)
    or
    node instanceof Sanitizer
  }
}

private module CleartextLoggingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink) }

  predicate isAdditionalFlowStep(DataFlow::Node prev, DataFlow::Node next){ isFixStep(prev, next) }
}

/** Global taint-tracking for detecting "Clear-text logging of sensitive information" vulnerabilities. */
module CleartextLoggingFlow = TaintTracking::Global<CleartextLoggingConfig>;
