import MySources
import MySinks
import MySummaries
/** Provides taint-tracking flow to reason about XPath injection queries. */

import java
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.TaintTracking
private import semmle.code.java.security.XPath

/**
 * A taint-tracking configuration for reasoning about XPath injection vulnerabilities.
 */
module XPathInjectionConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof ThreatModelFlowSource
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof XPathInjectionSink
  or isFixSink(sink)
}







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Taint-tracking flow for XPath injection vulnerabilities.
 */
module XPathInjectionFlow = TaintTracking::Global<XPathInjectionConfig>;
