import MySources
import MySinks
import MySummaries
/** Provides taint tracking configurations relating to Groovy injection vulnerabilities. */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.GroovyInjection

/**
 * DEPRECATED: Use `GroovyInjectionFlow` instead.
 *
 * A taint-tracking configuration for unsafe user input
 * that is used to evaluate a Groovy expression.
 */
deprecated class GroovyInjectionConfig extends TaintTracking::Configuration {
  GroovyInjectionConfig() { this = "GroovyInjectionConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof GroovyInjectionSink }

  override predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    any(GroovyInjectionAdditionalTaintStep c).step(fromNode, toNode)
  }
}

/**
 * A taint-tracking configuration for unsafe user input
 * that is used to evaluate a Groovy expression.
 */
module GroovyInjectionConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof ThreatModelFlowSource
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof GroovyInjectionSink
  or isFixSink(sink)
}

  predicate isAdditionalFlowStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    any(GroovyInjectionAdditionalTaintStep c).step(fromNode, toNode)
  or isFixStep(fromNode, toNode)
}






}

/**
 * Detect taint flow of unsafe user input
 * that is used to evaluate a Groovy expression.
 */
module GroovyInjectionFlow = TaintTracking::Global<GroovyInjectionConfig>;
