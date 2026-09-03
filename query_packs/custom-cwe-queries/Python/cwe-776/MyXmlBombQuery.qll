import MySources
import MySinks
import MySummaries
/**
 * Provides a taint-tracking configuration for detecting "XML bomb" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `Configuration` is needed, otherwise
 * `XmlBombCustomizations` should be imported instead.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import XmlBombCustomizations::XmlBomb

/**
 * DEPRECATED: Use `XmlBombFlow` module instead.
 *
 * A taint-tracking configuration for detecting "XML bomb" vulnerabilities.
 */
deprecated class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "XmlBomb" }

  override predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink) }

  override predicate isSanitizer(DataFlow::Node node) {
    super.isSanitizer(node) or
    node instanceof Sanitizer
  }
}

private module XmlBombConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink) }

  predicate isAdditionalFlowStep(DataFlow::Node prev, DataFlow::Node next){ isFixStep(prev, next) }
}

/** Global taint-tracking for detecting "XML bomb" vulnerabilities. */
module XmlBombFlow = TaintTracking::Global<XmlBombConfig>;
