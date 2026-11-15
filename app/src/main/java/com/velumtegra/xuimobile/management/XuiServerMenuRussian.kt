package com.velumtegra.xuimobile.management

internal data class XuiMenuSection(val title: String, val choices: List<XuiMenuChoice>)

private val mainMenu = linkedMapOf(
    "Службы и журналы" to mapOf(
        "Start" to "Запустить x-ui",
        "Stop" to "Остановить x-ui",
        "Restart" to "Перезапустить x-ui",
        "Restart Xray" to "Перезапустить Xray",
        "Check Status" to "Проверить состояние x-ui",
        "Logs Management" to "Журналы x-ui",
        "Enable Autostart" to "Включить автозапуск x-ui",
        "Disable Autostart" to "Выключить автозапуск x-ui",
    ),
    "Настройки и доступ" to mapOf(
        "Reset Username & Password" to "Сбросить логин и пароль",
        "Reset Web Base Path" to "Сбросить путь панели",
        "Reset Settings" to "Сбросить настройки панели",
        "Change Port" to "Изменить порт панели",
        "View Current Settings" to "Показать текущие настройки",
    ),
    "Сертификаты и защита" to mapOf(
        "SSL Certificate Management" to "Сертификаты TLS",
        "Cloudflare SSL Certificate" to "Сертификат TLS через Cloudflare",
        "IP Limit Management" to "Ограничения по IP",
        "Firewall Management" to "Межсетевой экран",
        "SSH Port Forwarding Management" to "Проброс порта через SSH",
    ),
    "Установка и обновления" to mapOf(
        "Install" to "Установить x-ui",
        "Update" to "Обновить x-ui",
        "Update to Dev Channel (latest commit)" to "Обновить до версии для разработчиков",
        "Update Menu" to "Обновить скрипт меню",
        "Legacy Version" to "Установить предыдущую версию",
        "Uninstall" to "Удалить x-ui и Xray",
    ),
    "Инструменты сервера" to mapOf(
        "PostgreSQL Management" to "Управление PostgreSQL",
        "Enable BBR" to "Управление BBR",
        "Update Geo Files" to "Обновить геоданные Xray",
        "Speedtest by Ookla" to "Проверить скорость через Ookla",
    ),
    "Сеанс" to mapOf("Exit Script" to "Выйти из меню x-ui"),
)

private val submenus = mapOf(
    "Back to Main Menu" to "Вернуться в главное меню",
    "Debug Log" to "Открыть журнал отладки",
    "Clear All logs" to "Очистить все журналы",
    "Enable BBR" to "Включить BBR",
    "Disable BBR" to "Выключить BBR",
    "Install Firewall" to "Установить межсетевой экран",
    "Port List [numbered]" to "Показать список портов с номерами правил",
    "Open Ports" to "Открыть порты",
    "Delete Ports from List" to "Удалить правила для портов",
    "Enable Firewall" to "Включить межсетевой экран",
    "Disable Firewall" to "Выключить межсетевой экран",
    "Firewall Status" to "Проверить состояние межсетевого экрана",
    "Rule numbers" to "По номерам правил",
    "Ports" to "По номерам портов",
    "All" to "Все наборы",
    "Get SSL (Domain)" to "Выпустить сертификат для домена",
    "Revoke & Remove" to "Отозвать и удалить сертификат",
    "Force Renew" to "Принудительно продлить сертификат",
    "Show Existing Domains" to "Показать домены с сертификатами",
    "Set Cert paths for the panel" to "Указать файлы сертификата и ключа для панели",
    "Get SSL for IP Address (6-day cert, auto-renews)" to "Выпустить сертификат для IP на 6 дней с автопродлением",
    "Use a certificate from /root/cert" to "Выбрать сертификат из /root/cert",
    "Enter custom certificate file paths (e.g. certbot, /etc/letsencrypt/...)" to "Ввести свои пути к файлам сертификата",
    "Preset: systemctl reload nginx ; x-ui restart" to "Перезагрузить конфигурацию Nginx и перезапустить x-ui",
    "Input your own command" to "Ввести свою команду",
    "Keep default reloadcmd" to "Оставить стандартную команду перезагрузки",
    "Install Fail2ban and configure IP Limit" to "Установить Fail2ban и настроить ограничения по IP",
    "Change Ban Duration" to "Изменить срок блокировки",
    "Unban Everyone" to "Снять блокировку со всех IP",
    "Ban Logs" to "Открыть журнал блокировок",
    "Ban an IP Address" to "Заблокировать IP-адрес",
    "Unban an IP Address" to "Снять блокировку с IP-адреса",
    "Real-Time Logs" to "Смотреть журнал в реальном времени",
    "Service Status" to "Проверить состояние Fail2ban",
    "Service Restart" to "Перезапустить Fail2ban",
    "Uninstall Fail2ban and IP Limit" to "Удалить Fail2ban и ограничения по IP",
    "Only remove IP Limit configurations" to "Удалить только настройки ограничений по IP",
    "Set listen IP" to "Задать IP-адрес прослушивания",
    "Clear listen IP" to "Очистить IP-адрес прослушивания",
    "Use default IP (127.0.0.1)" to "Использовать локальный IP 127.0.0.1",
    "Set a custom IP" to "Указать другой IP",
    "Install PostgreSQL locally and create a dedicated user/db (recommended)" to "Установить PostgreSQL и создать пользователя и базу",
    "Use an existing PostgreSQL server (enter DSN)" to "Подключить существующий PostgreSQL по DSN",
    "Install PostgreSQL (server + client + xui db)" to "Установить PostgreSQL, клиент и базу x-ui",
    "Migrate SQLite -> PostgreSQL" to "Перенести базу SQLite в PostgreSQL",
    "Status (clusters & port 5432)" to "Проверить кластеры и порт PostgreSQL 5432",
    "Start PostgreSQL" to "Запустить PostgreSQL",
    "Stop PostgreSQL" to "Остановить PostgreSQL",
    "Restart PostgreSQL" to "Перезапустить PostgreSQL",
    "Enable Autostart on boot" to "Включить автозапуск PostgreSQL",
    "View PostgreSQL Log" to "Открыть журнал PostgreSQL",
    "Convert SQLite .db <-> .dump" to "Преобразовать SQLite между .db и .dump",
    "Install/Upgrade client tools (pg_dump/pg_restore)" to "Установить или обновить pg_dump и pg_restore",
)

private val mainLabels = mainMenu.values.flatMap { it.entries }.associate { it.toPair() }
private val space = Regex("\\s+")
private fun labelKey(label: String) = label.trim().replace(space, " ")

internal fun xuiMainMenu(prompt: XuiMenuPrompt?): Boolean =
    prompt != null && prompt.text.startsWith("Please enter your selection", ignoreCase = true) &&
        prompt.choices.count { labelKey(it.label) in mainLabels } >= 2

internal fun xuiMenuSections(prompt: XuiMenuPrompt?): List<XuiMenuSection> {
    val choices = prompt?.choices.orEmpty()
    if (choices.isEmpty()) return emptyList()
    if (!xuiMainMenu(prompt)) return listOf(XuiMenuSection("Команды сервера", choices))

    val sections = mainMenu.mapNotNull { (title, labels) ->
        choices.filter { labelKey(it.label) in labels }.takeIf { it.isNotEmpty() }?.let { XuiMenuSection(title, it) }
    }
    val unknown = choices.filter { labelKey(it.label) !in mainLabels }
    return if (unknown.isEmpty()) sections else sections + XuiMenuSection("Другие команды сервера", unknown)
}

internal fun russianXuiChoice(choice: XuiMenuChoice, main: Boolean): String =
    (if (main) mainLabels else submenus)[labelKey(choice.label)] ?: choice.label

internal fun xuiMenuReturnPrompt(text: String): Boolean =
    text.equals("Press enter to return to the main menu:", ignoreCase = true)

private val plainPrompts = mapOf(
    "Please enter your server's public IPv4 address" to "Введите публичный IPv4-адрес сервера.",
    "Enter port number[1-65535]" to "Введите номер порта от 1 до 65535.",
    "Enter the panel version (like 2.4.0)" to "Введите версию x-ui, например 2.4.0.",
    "Enter the ports you want to open (e.g. 80,443,2053 or range 400-500)" to "Введите порты для открытия. Можно указать список через запятую или диапазон через дефис.",
    "Enter the rule numbers you want to delete (1, 2, etc.)" to "Введите номера правил для удаления через запятую.",
    "Enter the ports you want to delete (e.g. 80,443,2053 or range 400-500)" to "Введите порты, для которых нужно удалить правила. Можно указать список или диапазон.",
    "Please enter a domain from the list to revoke and remove the certificate" to "Введите домен из списка, чтобы отозвать и удалить его сертификат.",
    "Please enter a domain from the list to renew the SSL certificate" to "Введите домен из списка, чтобы продлить его сертификат.",
    "Please choose a domain to set the panel paths" to "Введите домен, сертификат которого будет использовать панель.",
    "Do you have an IPv6 address to include? (leave empty to skip)" to "Введите IPv6-адрес или оставьте поле пустым.",
    "Port to use for ACME HTTP-01 listener (default 80)" to "Введите порт для проверки ACME HTTP-01. По умолчанию 80.",
    "Enter another port for acme.sh standalone listener (leave empty to abort)" to "Введите другой порт для acme.sh или оставьте поле пустым для отмены.",
    "Please enter your domain name" to "Введите домен.",
    "Please choose which port to use (default is 80)" to "Введите порт. По умолчанию 80.",
    "Input your domain here" to "Введите домен Cloudflare.",
    "Please enter new Ban Duration in Minutes [default 30]" to "Введите время блокировки в минутах. По умолчанию 30.",
    "Enter the IP address you want to ban" to "Введите IP-адрес для блокировки.",
    "Enter the IP address you want to unban" to "Введите IP-адрес, с которого нужно снять блокировку.",
    "Enter custom IP to listen on" to "Введите IP-адрес прослушивания.",
    "Required PostgreSQL major version (empty = any)" to "Введите основную версию PostgreSQL или оставьте поле пустым.",
)

private val maskedPrompts = mapOf(
    "Please set the login username [default is a random username]" to "Введите новый логин панели. Если оставить поле пустым, сервер создаст случайный.",
    "Please set the login password [default is a random password]" to "Введите новый пароль панели. Если оставить поле пустым, сервер создаст случайный.",
    "Certificate file path (fullchain)" to "Введите путь к файлу цепочки сертификатов (fullchain).",
    "Private key file path" to "Введите путь к файлу закрытого ключа.",
    "Please enter your reloadcmd (example: systemctl reload nginx ; x-ui restart)" to "Введите команду, которую ACME выполнит после обновления сертификата.",
    "Input your key here" to "Введите глобальный ключ API Cloudflare.",
    "Input your email here" to "Введите почту аккаунта Cloudflare.",
    "Input your token here" to "Введите токен API Cloudflare.",
    "Enter PostgreSQL DSN (postgres://user:pass@host:port/dbname?sslmode=disable)" to "Введите строку подключения PostgreSQL (DSN).",
    "Output file (leave empty to auto-name next to input)" to "Введите путь для сохранения. Если оставить поле пустым, сервер создаст имя рядом с исходным файлом.",
    "Are you using a Cloudflare API Token or Global API Key? (t/g) [Default t]" to "Введите t для токена API или g для глобального ключа Cloudflare. По умолчанию токен.",
)

private val questions = mapOf(
    "This function will update all x-ui components to the latest version, and the data will not be lost. Do you want to continue?" to "Обновить все компоненты x-ui до последней версии с сохранением данных?",
    "This will update x-ui to the latest DEV commit (the rolling 'dev-latest' build, not a stable release). Your data is preserved. Continue?" to "Установить последнюю сборку для разработчиков с сохранением данных?",
    "Are you sure you want to uninstall the panel? xray will also uninstalled!" to "Удалить панель x-ui вместе с Xray?",
    "Are you sure to reset the username and password of the panel?" to "Сбросить логин и пароль панели?",
    "Do you want to disable currently configured two-factor authentication?" to "Выключить двухфакторную аутентификацию панели?",
    "Are you sure you want to reset the web base path?" to "Сбросить путь веб-панели?",
    "Generate SSL certificate for IP now?" to "Выпустить сертификат для IP-адреса сейчас?",
    "Would you like to set this certificate for the panel?" to "Использовать этот сертификат в панели?",
    "Would you like to modify --reloadcmd for ACME?" to "Изменить команду перезагрузки для ACME?",
    "Do you want to proceed?" to "Продолжить?",
    "Do you confirm the information and wish to proceed?" to "Подтверждаете данные и хотите продолжить?",
    "Proceed with installation of Fail2ban & IP Limit?" to "Установить Fail2ban и настроить ограничения по IP?",
    "Proceed with Unbanning everyone from IP Limit jail?" to "Снять блокировку со всех IP?",
    "Also purge PostgreSQL and delete all of its data?" to "Также удалить PostgreSQL вместе со всеми его данными?",
    "Run setup anyway (ensures the xui database/user exist)?" to "Запустить настройку, чтобы убедиться, что база и пользователь x-ui созданы?",
    "Continue?" to "Продолжить?",
    "Migrate into this database?" to "Перенести данные в эту базу?",
)

private val answerSuffix = Regex("""(?:\s+(?:\[[yY]/[nN]\]|\([yY]/[nN]\)|\[Default [ynYN]\]))+$""")
private val inputFile = Regex("""Input file \[(.+)]""")
private val confirmAddress = Regex("""Is (.+) the correct incoming public IPv4 address for this server\?""")
private val confirmOverwrite = Regex("""Output (.+) already exists and will be overwritten\. Continue\?""")
private val enterSelection = Regex("""(?i)(?:please )?enter your selection(?: \[[0-9]+-[0-9]+])?""")
private val chooseOption = Regex("""(?i)(?:choose an option|(?:enter your choice|select an option) \(1 or 2\)|choose \[[0-9]+])""")

internal fun russianXuiPrompt(text: String): String {
    if (xuiMenuReturnPrompt(text)) return "Команда завершена."
    val key = text.trimEnd(':').trim()
    if (enterSelection.matches(key) || chooseOption.matches(key)) return "Выберите команду."
    plainPrompts[key]?.let { return it }
    maskedPrompts[key]?.let { return it }

    val question = key.replace(answerSuffix, "")
    questions[question]?.let { return it }
    inputFile.matchEntire(key)?.let { return "Введите путь к исходному файлу. По умолчанию ${it.groupValues[1]}." }
    confirmAddress.matchEntire(question)?.let { return "Подтвердить ${it.groupValues[1]} как публичный IPv4-адрес сервера?" }
    confirmOverwrite.matchEntire(question)?.let { return "Файл ${it.groupValues[1]} уже существует. Перезаписать его?" }
    return text
}

internal fun xuiPromptMasksInput(text: String?): Boolean =
    text == null || !plainPrompts.containsKey(text.trimEnd(':').trim())

private val defaultAnswer = Regex("""(?i:\[default\s)|\[Y/n]|\[y/N]""")

internal fun xuiEmptyReplyLabel(text: String?): String =
    if (text != null && defaultAnswer.containsMatchIn(text)) {
        "По умолчанию"
    } else {
        "Пустой ответ"
    }

private val serviceStates = mapOf(
    "Running" to "работает",
    "Not Running" to "остановлен",
    "Not Installed" to "не установлен",
)
private val autostartStates = mapOf(
    "Yes" to "включён",
    "No" to "выключен",
    "Managed by Docker" to "управляется Docker",
)

internal fun russianXuiStatus(turnOutput: String): List<String> {
    val rows = cleanXuiMenuOutput(turnOutput).lines().associate {
        it.substringBefore(':').trim() to it.substringAfter(':', "").trim()
    }
    return listOfNotNull(
        rows["Panel state"]?.let(serviceStates::get)?.let { "x-ui $it" },
        rows["xray state"]?.let(serviceStates::get)?.let { "Xray $it" },
        rows["Start automatically"]?.let(autostartStates::get)?.let { "автозапуск $it" },
    )
}
