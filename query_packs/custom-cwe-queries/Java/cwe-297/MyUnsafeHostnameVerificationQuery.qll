import MySources
import MySinks
import MySummaries
/** Provides predicates and dataflow configurations for reasoning about unsafe hostname verification. */

import java
private import semmle.code.java.controlflow.Guards
private import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.security.Encryption
private import semmle.code.java.security.SecurityFlag
private import semmle.code.java.dataflow.ExternalFlow

/**
 * Holds if `m` always returns `true` ignoring any exceptional flow.
 */
private predicate alwaysReturnsTrue(HostnameVerifierVerify m) {
  forex(ReturnStmt rs | rs.getEnclosingCallable() = m |
    rs.getResult().(CompileTimeConstantExpr).getBooleanValue() = true
  )
}

/**
 * A class that overrides the `javax.net.ssl.HostnameVerifier.verify` method and **always** returns `true` (though it could also exit due to an uncaught exception), thus
 * accepting any certificate despite a hostname mismatch.
 */
class TrustAllHostnameVerifier extends RefType {
  TrustAllHostnameVerifier() {
    this.getAnAncestor() instanceof HostnameVerifier and
    exists(HostnameVerifierVerify m |
      m.getDeclaringType() = this and
      alwaysReturnsTrue(m)
    )
  }
}

/**
 * A configuration to model the flow of a `TrustAllHostnameVerifier` to a `set(Default)HostnameVerifier` call.
 */
module TrustAllHostnameVerifierConfig implements DataFlow::ConfigSig {






  predicate isSource(DataFlow::Node source) {
    source.asExpr().(ClassInstanceExpr).getConstructedType() instanceof TrustAllHostnameVerifier
  or isFixSource(source)
}

  predicate isSink(DataFlow::Node sink) { sink instanceof HostnameVerifierSink
  or isFixSink(sink)
}

predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  isFixStep(n1, n2)
}




}

/** Data flow to model the flow of a `TrustAllHostnameVerifier` to a `set(Default)HostnameVerifier` call. */
module TrustAllHostnameVerifierFlow = DataFlow::Global<TrustAllHostnameVerifierConfig>;

/**
 * A sink that sets the `HostnameVerifier` on `HttpsURLConnection`.
 */
private class HostnameVerifierSink extends DataFlow::Node {
  HostnameVerifierSink() { sinkNode(this, "hostname-verification") }
}

/**
 * Flags suggesting a deliberately unsafe `HostnameVerifier` usage.
 */
private class UnsafeHostnameVerificationFlag extends FlagKind {
  UnsafeHostnameVerificationFlag() { this = "UnsafeHostnameVerificationFlag" }

  bindingset[result]
  override string getAFlagName() {
    result
        .regexpMatch("(?i).*(secure|disable|selfCert|selfSign|validat|verif|trust|ignore|nocertificatecheck).*") and
    result != "equalsIgnoreCase"
  }
}

/** Gets a guard that represents a (likely) flag controlling an unsafe `HostnameVerifier` use. */
private Guard getAnUnsafeHostnameVerifierFlagGuard() {
  result = any(UnsafeHostnameVerificationFlag flag).getAFlag().asExpr()
}

/** Holds if `node` is guarded by a flag that suggests an intentionally insecure use. */
predicate isNodeGuardedByFlag(DataFlow::Node node) {
  exists(Guard g | g.controls(node.asExpr().getBasicBlock(), _) |
    g = getASecurityFeatureFlagGuard() or g = getAnUnsafeHostnameVerifierFlagGuard()
  )
}
