package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v0.9.7 (канон «явные статусы согласования»): совпало — молчим;
 * AUTO-даунгрейд и непосещённый явный proto — честный WARN с метками.
 */
class NegotiationTest {

    @Test
    fun matchingProtocolsAreSilent() {
        assertNull(Negotiation.notice("rrp1", "rrp1", "rrp1"))
        assertNull(Negotiation.notice("mtproto2", "mtproto2", ""))
        assertNull(Negotiation.notice(RrpProtocols.PREFERRED_AUTO, RrpProtocols.PREFERRED_AUTO, ""))
    }

    @Test
    fun autoDowngradeNamesPreferredAndGranted() {
        val n = Negotiation.notice(RrpProtocols.PREFERRED_AUTO, RrpProtocols.DEFAULT, "")!!
        assertTrue(n.contains(RrpProtocols.labelWithVer(RrpProtocols.PREFERRED_AUTO)))
        assertTrue(n.contains(RrpProtocols.labelWithVer(RrpProtocols.DEFAULT)))
    }

    @Test
    fun explicitNotGrantedNamesRequestedAndActual() {
        val n = Negotiation.notice("mtproto2", "rrp1", "mtproto2")!!
        assertTrue(n.contains(RrpProtocols.labelWithVer("mtproto2")))
        assertTrue(n.contains(RrpProtocols.labelWithVer("rrp1")))
    }

    @Test
    fun autoAndExplicitUseDifferentWordings() {
        val auto = Negotiation.notice(RrpProtocols.PREFERRED_AUTO, RrpProtocols.DEFAULT, "")!!
        val explicit = Negotiation.notice(RrpProtocols.PREFERRED_AUTO, RrpProtocols.DEFAULT, "wireguard")!!
        assertTrue(auto != explicit)
    }
}
