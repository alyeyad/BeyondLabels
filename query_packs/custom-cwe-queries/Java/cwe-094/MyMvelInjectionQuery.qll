import MySources
import MySinks
import MySummaries
/** Provides taint tracking configurations to be used in MVEL injection related queries. */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.MvelInjection

/**
 * DEPRECATED: Use `MvelInjectionFlow` instead.
 *
 * A taint-tracking configuration for unsafe user input
 * that is used to construct and evaluate a MVEL expression.
 */
deprecated class MvelInjectionFlowConfig extends TaintTracking::Configuration {
  MvelInjectionFlowConfig() { this = "MvelInjectionFlowConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof MvelEvaluationSink }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof MvelInjectionSanitizer
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(MvelInjectionAdditionalTaintStep c).step(node1, node2)
  }
}

/**
 * A taint-tracking configuration for unsafe user input
 * that is used to construct and evaluate a MVEL expression.
 */
module MvelInjectionFlowConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof ThreatModelFlowSource
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof MvelEvaluationSink
  or isFixSink(sink)
}

predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(MvelInjectionAdditionalTaintStep c).step(node1, node2)
  or isFixStep(node1, node2)
}






}

/** Tracks flow of unsafe user input that is used to construct and evaluate a MVEL expression. */
module MvelInjectionFlow = TaintTracking::Global<MvelInjectionFlowConfig>;
