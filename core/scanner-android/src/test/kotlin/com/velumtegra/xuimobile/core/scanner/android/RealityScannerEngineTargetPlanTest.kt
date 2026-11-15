package com.velumtegra.xuimobile.core.scanner.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RealityScannerEngineTargetPlanTest {
    private val engine = RealityScannerEngine()

    @Test
    fun singleIpv4UsesCanonicalSymmetricProducer() {
        val plan = engine.planTargets("198.51.100.10", enableIpv6 = false)

        assertTrue(plan.infinite)
        assertEquals(0, plan.total)
        assertEquals(
            listOf(
                "198.51.100.10",
                "198.51.100.9",
                "198.51.100.11",
                "198.51.100.8",
                "198.51.100.12",
                "198.51.100.7",
                "198.51.100.13",
            ),
            plan.targets.take(7).map { it.host }.toList(),
        )
    }

    @Test
    fun singleIpv4DoesNotRegressToCumulativeOffsets() {
        val hosts =
            engine.planTargets("203.0.113.20", enableIpv6 = false)
                .targets
                .take(7)
                .map { it.host }
                .toList()

        assertFalse("203.0.113.17" in hosts.take(5))
        assertEquals("203.0.113.18", hosts[3])
        assertEquals("203.0.113.22", hosts[4])
    }

    @Test
    fun ipv4CidrRemainsFiniteAndKeepsCidrOrigin() {
        val plan = engine.planTargets("192.0.2.4/30", enableIpv6 = false)
        val targets = plan.targets.toList()

        assertFalse(plan.infinite)
        assertEquals(4, plan.total)
        assertEquals(
            listOf("192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"),
            targets.map { it.host },
        )
        assertTrue(targets.all { it.origin == "192.0.2.4/30" && !it.isDomain })
    }

    @Test
    fun domainRemainsFiniteAndUnchanged() {
        val plan = engine.planTargets("example.com", enableIpv6 = false)
        val target = plan.targets.single()

        assertFalse(plan.infinite)
        assertEquals(1, plan.total)
        assertEquals("example.com", target.origin)
        assertEquals("example.com", target.host)
        assertTrue(target.isDomain)
    }

    @Test
    fun pastedUrlAndHostPortAreReducedToTheHost() {
        assertEquals("example.com", engine.planTargets("https://Example.com:8443/path?x=1", false).targets.single().host)
        assertEquals("example.com", engine.planTargets(" example.com. ", false).targets.single().host)

        val ip = engine.planTargets("198.51.100.10:443", enableIpv6 = false)
        assertTrue(ip.infinite)
        assertEquals("198.51.100.10", ip.targets.first().host)

        val bracketed = engine.planTargets("[2001:db8::10]:443", enableIpv6 = true)
        assertTrue(bracketed.infinite)
        assertEquals("2001:db8:0:0:0:0:0:10", bracketed.targets.first().host)
    }

    @Test
    fun commaAndSpaceSeparatedTargetsFormOneFiniteList() {
        val plan = engine.planTargets("198.51.100.10, example.com;192.0.2.4/31\n198.51.100.10", enableIpv6 = false)

        assertFalse(plan.infinite)
        assertEquals(4, plan.total)
        assertEquals(
            listOf("198.51.100.10", "example.com", "192.0.2.4", "192.0.2.5"),
            plan.targets.map { it.host }.toList(),
        )
    }

    @Test
    fun largestAllowedCidrIsPlannedWithoutMaterializingIt() {
        val plan = engine.planTargets("10.0.0.0/12", enableIpv6 = false)

        assertEquals(1 shl 20, plan.total)
        assertEquals(listOf("10.0.0.0", "10.0.0.1"), plan.targets.take(2).map { it.host }.toList())
        assertEquals("10.15.255.255", plan.targets.drop((1 shl 20) - 1).single().host)
    }

    @Test
    fun unusableInputIsExplainedInsteadOfSilentlyRejected() {
        assertEquals(null, engine.inputProblem("198.51.100.10", enableIpv6 = false))
        assertEquals(null, engine.inputProblem("localhost", enableIpv6 = false))
        assertEquals("Укажи IP, домен или CIDR.", engine.inputProblem("  ", enableIpv6 = false))
        assertTrue(engine.inputProblem("2001:db8::10", enableIpv6 = false)!!.contains("IPv6"))
        assertTrue(engine.inputProblem("10.0.0.0/8", enableIpv6 = false)!!.contains("CIDR"))
        assertTrue(engine.inputProblem("1.2.3.999", enableIpv6 = false)!!.contains("Не найдено"))
        assertTrue(engine.inputProblem("-bad-.example", enableIpv6 = false)!!.contains("Не найдено"))
    }

    @Test
    fun inputSummaryTellsNeighbourScanFromFiniteList() {
        assertEquals(RealityScanInputSummary(infinite = true, total = 0), engine.summarizeInput("198.51.100.10", false))
        assertEquals(RealityScanInputSummary(infinite = false, total = 1), engine.summarizeInput("example.com", false))
        assertEquals(RealityScanInputSummary(infinite = false, total = 256), engine.summarizeInput("192.0.2.0/24", false))
        assertEquals(null, engine.summarizeInput("???", false))
    }

    @Test
    fun exactIpv6RequiresExplicitToggle() {
        assertThrows(IllegalArgumentException::class.java) {
            engine.planTargets("2001:db8::10", enableIpv6 = false)
        }

        val plan = engine.planTargets("2001:db8::10", enableIpv6 = true)
        assertTrue(plan.infinite)
        assertEquals(
            listOf("2001:db8:0:0:0:0:0:10", "2001:db8:0:0:0:0:0:f", "2001:db8:0:0:0:0:0:11"),
            plan.targets.take(3).map { it.host }.toList(),
        )
    }
}
