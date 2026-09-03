import MySources
import MySinks
import MySummaries
/** Definitions for the RSA without OAEP query */

import java
import Encryption
import semmle.code.java.dataflow.DataFlow

/**
 * DEPRECATED: Use `RsaWithoutOaepFlow` instead.
 *
 * A configuration for finding RSA ciphers initialized without using OAEP padding.
 */
deprecated class RsaWithoutOaepConfig extends DataFlow::Configuration {
  RsaWithoutOaepConfig() { this = "RsaWithoutOaepConfig" }

  override predicate isSource(DataFlow::Node src) {
    exists(CompileTimeConstantExpr specExpr, string spec |
      specExpr.getStringValue() = spec and
      specExpr = src.asExpr() and
      spec.matches("RSA/%") and
      not spec.matches("%OAEP%")
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(CryptoAlgoSpec cr | sink.asExpr() = cr.getAlgoSpec())
  }
}

/**
 * A configuration for finding RSA ciphers initialized without using OAEP padding.
 */
module RsaWithoutOaepConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node src) {
    exists(CompileTimeConstantExpr specExpr, string spec |
      specExpr.getStringValue() = spec and
      specExpr = src.asExpr() and
      spec.matches("RSA/%") and
      not spec.matches("%OAEP%")
    )
  or isFixSource(src)
}

  predicate isSink(DataFlow::Node sink) {
    exists(CryptoAlgoSpec cr | sink.asExpr() = cr.getAlgoSpec())
  or isFixSink(sink)
}







predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/** Flow for finding RSA ciphers initialized without using OAEP padding. */
module RsaWithoutOaepFlow = DataFlow::Global<RsaWithoutOaepConfig>;
