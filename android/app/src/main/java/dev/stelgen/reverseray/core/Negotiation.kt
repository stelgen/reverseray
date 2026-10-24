package dev.stelgen.reverseray.core

/**
 * v0.9.7 (канон «явные статусы согласования»): сервер, не умеющий
 * запрошенный протокол, честно даунгрейдит согласование вниз до самого
 * стабильного (rrp1) — НО клиент не имеет права молчать: пользователь
 * должен видеть, на чём реально работает туннель.
 *
 * Случаи:
 *  - запрошено == прислано → null (совпало, уведомление не нужно);
 *  - ссылка без proto= (AUTO, claimed пуст): клиент просил предпочтительный
 *    (PREFERRED_AUTO = wireguard), сервер согласовал ниже → WARN
 *    «сервер не поддерживает X — согласован Y»;
 *  - явный proto=X в ссылке, сервер не подтвердил → WARN
 *    «сервер не подтвердил X — работаю на Y».
 *
 * Чистая функция (JVM-тесты) — только форматирование, без андроид-зависимостей.
 */
object Negotiation {

    /**
     * Текст уведомления о несоответствии согласования или null.
     * @param requested протокол, который клиент запросил в HELLO
     *                  (для AUTO — предпочтительный, PREFERRED_AUTO)
     * @param negotiated протокол, который сервер прислал в READY
     * @param claimed протокол КАК В ССЫЛКЕ ("" = AUTO)
     */
    fun notice(requested: String, negotiated: String, claimed: String): String? {
        if (requested == negotiated) return null
        val from = RrpProtocols.labelWithVer(requested)
        val to = RrpProtocols.labelWithVer(negotiated)
        return if (claimed.isBlank()) {
            Msgs.PROTO_AUTO_DOWNGRADED.t(from, to)
        } else {
            Msgs.PROTO_NOT_GRANTED.t(from, to)
        }
    }
}
