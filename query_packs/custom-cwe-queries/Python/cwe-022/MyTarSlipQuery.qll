import MySources
import MySinks
import MySummaries
/**
 * Provides a taint-tracking configuration for detecting "tar slip" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `TarSlip::Configuration` is needed, otherwise
 * `TarSlipCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import TarSlipCustomizations::TarSlip

/**
 * DEPRECATED: Use `TarSlipFlow` module instead.
 *
 * A taint-tracking configuration for detecting "tar slip" vulnerabilities.
 */
deprecated class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "TarSlip" }

  override predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink) }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }
}

private module TarSlipConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink)}
  
  predicate isAdditionalFlowStep(DataFlow::Node prev, DataFlow::Node next){ isFixStep(prev, next) }
}

/** Global taint-tracking for detecting "tar slip" vulnerabilities. */
module TarSlipFlow = TaintTracking::Global<TarSlipConfig>;
