import MySources
import MySinks
import MySummaries
/**
 * Provides a taint tracking configuration for reasoning about shell command
 * constructed from library input vulnerabilities
 *
 * Note, for performance reasons: only import this file if `Configuration` is needed,
 * otherwise `UnsafeShellCommandConstructionCustomizations` should be imported instead.
 */

import python
import semmle.python.dataflow.new.DataFlow
import UnsafeShellCommandConstructionCustomizations::UnsafeShellCommandConstruction
private import semmle.python.dataflow.new.TaintTracking
private import CommandInjectionCustomizations::CommandInjection as CommandInjection
private import semmle.python.dataflow.new.BarrierGuards

/**
 * DEPRECATED: Use `UnsafeShellCommandConstructionFlow` module instead.
 *
 * A taint-tracking configuration for detecting shell command constructed from library input vulnerabilities.
 */
deprecated class Configuration extends TaintTracking::Configuration {
  Configuration() { this = "UnsafeShellCommandConstruction" }

  override predicate isSource(DataFlow::Node source) { source instanceof Source or isFixSource(source) }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Sink or isFixSink(sink) }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof Sanitizer or
    node instanceof CommandInjection::Sanitizer // using all sanitizers from `py/command-injection`
  }

  // override to require the path doesn't have unmatched return steps
  override DataFlow::FlowFeature getAFeature() {
    result instanceof DataFlow::FeatureHasSourceCallContext
  }
}

/**
 * A taint-tracking configuration for detecting "shell command constructed from library input" vulnerabilities.
 */
module UnsafeShellCommandConstructionConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof Source
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof Sink
  or isFixSink(sink)
}

// override to require the path doesn't have unmatched return steps
  DataFlow::FlowFeature getAFeature() { result instanceof DataFlow::FeatureHasSourceCallContext }







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/** Global taint-tracking for detecting "shell command constructed from library input" vulnerabilities. */
module UnsafeShellCommandConstructionFlow =
  TaintTracking::Global<UnsafeShellCommandConstructionConfig>;
