import MySources
import MySinks
import MySummaries
/**
 * Provides a taint-tracking configuration for detecting "command injection" vulnerabilities.
 *
 * Note, for performance reasons: only import this file if
 * `CommandInjection::Configuration` is needed, otherwise
 * `CommandInjectionCustomizations` should be imported instead.
 */

private import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import CommandInjectionCustomizations::CommandInjection

/**
 * DEPRECATED: Use `CommandInjectionFlow` module instead.
 *
 * A taint-tracking configuration for detecting "command injection" vulnerabilities.
 */
deprecated class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "CommandInjection" }

  override predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink) }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }
}

/**
 * A taint-tracking configuration for detecting "command injection" vulnerabilities.
 */
module CommandInjectionConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof Source
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink
  or isFixSink(sink)
}

predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/** Global taint-tracking for detecting "command injection" vulnerabilities. */
module CommandInjectionFlow = TaintTracking::Global<CommandInjectionConfig>;
