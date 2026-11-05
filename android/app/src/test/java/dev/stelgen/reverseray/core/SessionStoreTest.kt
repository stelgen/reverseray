package dev.stelgen.reverseray.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Тесты хранилища профилей v1.5.0: миграция, CRUD, зеркалирование KEY_CONFIG. */
class SessionStoreTest {

    /** in-memory backend (без android). */
    private class MapBackend : SessionStore.Backend {
        val map = HashMap<String, String>()
        override fun getString(key: String): String? = map[key]
        override fun putString(key: String, value: String) { map[key] = value }
        override fun remove(key: String) { map.remove(key) }
        override fun contains(key: String): Boolean = map.containsKey(key)
    }

    private val link =
        "rrp://tok123@srv.example.com:4433/?pin=AAAA&name=Home&proto=rrp1"
    private val link2 = "rrp://tok456@srv2.example.com:8443/"

    @Test
    fun migrationV13ToV15_becomesProfileOnePrimary() {
        val b = MapBackend()
        b.map["config"] = link
        val store = SessionStore(b)

        val p = store.migrateLegacy(link)
        assertNotNull(p)
        assertEquals(1, store.profiles().size)
        assertEquals(p!!.id, store.activeId())
        assertTrue(p.enabled)
        // токен/пин/хост/порты сохранены байт-в-байт (канонизация без потерь)
        val cfg = RrpUri.parse(p.uri)
        assertEquals("tok123", cfg.token)
        assertEquals("srv.example.com", cfg.host)
        assertEquals(listOf(4433), cfg.ports)
        assertEquals("AAAA", cfg.pin)
        assertEquals("Home", cfg.name)
        // миграция НЕ трогала legacy-ключ
        assertEquals(link, b.map["config"])
    }

    @Test
    fun migrationKeepsRawLink_whenParserFails() {
        val b = MapBackend()
        val garbage = "rrp://@:/" // невалидная ссылка
        b.map["config"] = garbage
        val store = SessionStore(b)
        val p = store.migrateLegacy(garbage)
        assertNotNull(p)
        assertEquals(garbage, p!!.uri) // потеря недопустима — сырьё сохранено
    }

    @Test
    fun migrationIsIdempotent_andNoopWithoutLegacy() {
        val b = MapBackend()
        b.map["config"] = link
        val store = SessionStore(b)
        val first = store.migrateLegacy(link)
        // повторный вызов ничего не делает (не затирает добавленное)
        store.add(link2, "S2")
        assertNull(store.migrateLegacy(link))
        assertEquals(2, store.profiles().size)

        val clean = SessionStore(MapBackend())
        assertNull(clean.migrateLegacy(null))
        assertTrue(clean.profiles().isEmpty())
        assertEquals(first, store.byId(store.activeId()))
    }

    @Test
    fun addEnableDisableRemove_roundtrip() {
        val store = SessionStore(MapBackend())
        store.migrateLegacy(null)

        val p = store.add(link2, "S2")
        assertNotNull(p)
        assertFalse(p!!.enabled) // дефолт: новые профили выключены
        assertEquals("S2", p.name)

        assertTrue(store.setEnabled(p.id, true))
        assertTrue(store.byId(p.id)!!.enabled)

        assertTrue(store.rename(p.id, "Home-2"))
        assertEquals("Home-2", store.byId(p.id)!!.name)

        assertTrue(store.remove(p.id))
        assertNull(store.byId(p.id))
        assertFalse(store.setEnabled(p.id, true)) // нет такого — false
    }

    @Test
    fun activePrimary_switchMirrorsLegacyKeyConfig() {
        val b = MapBackend()
        b.map["config"] = link
        val store = SessionStore(b)
        val p1 = store.migrateLegacy(link)!!
        // зеркалирование после миграции: канон в KEY_CONFIG
        assertEquals(RrpUri.parse(link).serialize(), b.map["config"])

        val p2 = store.add(link2, "S2")!!
        store.setEnabled(p2.id, true)
        store.setActive(p2.id)
        assertEquals(p2.id, store.activeId())
        assertEquals(RrpUri.parse(link2).serialize(), b.map["config"])

        // канон активного зеркалится даже после редактирования ссылки
        val edited = RrpUri.parse(link2).copy(proto = "mtproto2").serialize()
        store.update(p2.copy(uri = edited))
        store.setActive(p2.id)
        assertEquals(edited, b.map["config"])

        // удаление активного → PRIMARY = первый включённый
        store.remove(p2.id)
        assertEquals(p1.id, store.activeId())
        assertEquals(RrpUri.parse(link).serialize(), b.map["config"])
    }

    @Test
    fun clearActive_removesMirror() {
        val store = SessionStore(MapBackend())
        store.migrateLegacy(null)
        val p = store.add(link)!!
        store.setActive(p.id)
        assertTrue(store.setActive(null))
        assertNull(store.activeId())
        assertFalse(store.setActive("nonexistent"))
    }

    @Test
    fun addRejectsInvalidLink_andCapsProfiles() {
        val store = SessionStore(MapBackend())
        store.migrateLegacy(null)
        assertNull(store.add("not a link"))
        repeat(SessionStore.MAX_PROFILES - store.profiles().size) { n ->
            store.add("rrp://t$n@h$n:443/")
        }
        assertEquals(SessionStore.MAX_PROFILES, store.profiles().size)
        assertNull(store.add("rrp://over@over:443/")) // guardrail
    }
}
