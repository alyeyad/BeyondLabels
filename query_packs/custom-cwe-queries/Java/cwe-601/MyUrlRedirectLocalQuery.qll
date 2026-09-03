import MySources
import MySinks
import MySummaries
/** Provides a taint-tracking configuration to reason about URL redirection from local sources. */

import java
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.security.UrlRedirect

/**
 * A taint-tracking configuration to reason about URL redirection from local sources.
 */
module UrlRedirectLocalConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof LocalUserInput
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof UrlRedirectSink
  or isFixSink(sink)
}







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/**
 * Taint-tracking flow for URL redirection from local sources.
 */
module UrlRedirectLocalFlow = TaintTracking::Global<UrlRedirectLocalConfig>;
