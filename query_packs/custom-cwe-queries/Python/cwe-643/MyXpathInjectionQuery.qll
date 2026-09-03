import MySources
import MySinks
import MySummaries
/**
 * Provides a taint-tracking configuration for detecting "Xpath Injection" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `XpathInjection::Configuration` is needed, otherwise
 * `XpathInjectionCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import XpathInjectionCustomizations::XpathInjection

/**
 * DEPRECATED: Use `XpathInjectionFlow` module instead.
 *
 * A taint-tracking configuration for detecting "Xpath Injection" vulnerabilities.
 */
deprecated class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "Xpath Injection" }

  override predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink)  }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }
}

private module XpathInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink)  }

  predicate isAdditionalFlowStep(DataFlow::Node prev, DataFlow::Node next){ isFixStep(prev, next) }
}

/** Global taint-tracking for detecting "Xpath Injection" vulnerabilities. */
module XpathInjectionFlow = TaintTracking::Global<XpathInjectionConfig>;
