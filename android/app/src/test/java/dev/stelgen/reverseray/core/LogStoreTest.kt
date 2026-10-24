package dev.stelgen.reverseray.core

import dev.stelgen.reverseray.update.UpdateLogger
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * v0.9.7 ревизия централизованного логирования: кольцо LogStore, фильтры
 * каналов/экранов, новые-сверху, единственный источник (UpdateLogger тоже
 * пишет только в LogStore).
 */
class LogStoreTest {

    @Test
    fun ringKeepsCapacityAndDropsOldest() {
        LogStore.clear()
        repeat(LogStore.CAPACITY + 50) { LogStore.push("m$it", LogKind.INFO, LogStore.Channel.STATUS) }
        val snap = LogStore.snapshot(LogStore.Channel.STATUS)
        assertEquals(LogStore.CAPACITY, snap.size)
        assertEquals("m${LogStore.CAPACITY + 49}", snap.first().text) // новые сверху
        assertEquals("m50", snap.last().text) // 0..49 вытеснены
    }

    @Test
    fun snapshotFiltersByChannelNewestFirst() {
        LogStore.clear()
        LogStore.push("s1", LogKind.OK, LogStore.Channel.STATUS)
        LogStore.push("u1", LogKind.WARN, LogStore.Channel.UPDATE)
        LogStore.push("s2", LogKind.ERR, LogStore.Channel.STATUS)

        val status = LogStore.snapshot(LogStore.Channel.STATUS)
        assertEquals(listOf("s2", "s1"), status.map { it.text })
        assertEquals(listOf(LogKind.ERR, LogKind.OK), status.map { it.kind })

        assertEquals(listOf("u1"), LogStore.snapshot(LogStore.Channel.UPDATE).map { it.text })

        // без фильтра — всё, новые сверху
        assertEquals(listOf("s2", "u1", "s1"), LogStore.snapshot(null).map { it.text })
    }

    @Test
    fun screenMappingMatchesCanon() {
        assertEquals(LogStore.Channel.STATUS, LogStore.channelFor(LogStore.Screen.HOME))
        assertEquals(LogStore.Channel.UPDATE, LogStore.channelFor(LogStore.Screen.UPDATE))
        assertEquals(null, LogStore.channelFor(LogStore.Screen.LOG))

        LogStore.clear()
        LogStore.push("home", LogKind.OK, LogStore.Channel.STATUS)
        LogStore.push("upd", LogKind.WARN, LogStore.Channel.UPDATE)
        assertEquals(listOf("home"), LogStore.snapshotFor(LogStore.Screen.HOME).map { it.text })
        assertEquals(listOf("upd"), LogStore.snapshotFor(LogStore.Screen.UPDATE).map { it.text })
        assertEquals(listOf("upd", "home"), LogStore.snapshotFor(LogStore.Screen.LOG).map { it.text })
    }

    @Test
    fun updateLoggerWritesIntoSingleStore() {
        LogStore.clear()
        UpdateLogger.add("hello", LogKind.OK)
        UpdateLogger.add("info line")
        val snap = LogStore.snapshot(LogStore.Channel.UPDATE)
        assertEquals(listOf("info line", "hello"), snap.map { it.text })
        assertEquals(listOf(LogKind.INFO, LogKind.OK), snap.map { it.kind })
        // в STATUS от апдейтера ничего не попало
        assertEquals(0, LogStore.snapshot(LogStore.Channel.STATUS).size)
    }
}
