import MySources
import MySinks
import MySummaries
/** Provides taint tracking configurations to be used in Trust Manager queries. */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.InsecureTrustManager

/**
 * DEPRECATED: Use `InsecureTrustManagerFlow` instead.
 *
 * A configuration to model the flow of an insecure `TrustManager`
 * to the initialization of an SSL context.
 */
deprecated class InsecureTrustManagerConfiguration extends DataFlow::Configuration {
  InsecureTrustManagerConfiguration() { this = "InsecureTrustManagerConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof InsecureTrustManagerSource
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof InsecureTrustManagerSink }

  override predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    (this.isSink(node) or this.isAdditionalFlowStep(node, _)) and
    node.getType() instanceof Array and
    c instanceof DataFlow::ArrayContent
  }
}

/**
 * A configuration to model the flow of an insecure `TrustManager`
 * to the initialization of an SSL context.
 */
module InsecureTrustManagerConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) { source instanceof InsecureTrustManagerSource
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof InsecureTrustManagerSink
  or isFixSink(sink)
}

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    (isSink(node) or isAdditionalFlowStep(node, _)) and
    node.getType() instanceof Array and
    c instanceof DataFlow::ArrayContent
  }







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

module InsecureTrustManagerFlow = DataFlow::Global<InsecureTrustManagerConfig>;
