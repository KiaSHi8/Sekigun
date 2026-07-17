use crate::SecurityIssue;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::time::Duration;

// Глобальный базовый словарь (Общие уязвимости для всех стеков)
const BASE_DICTIONARY: &[&str] = &[
    ".env", "config.json", ".git/config", ".git/HEAD", "error_log", "debug.log"
];

// Специализированные словари (Подключаются динамически после разведки контура)
const BITRIX_DICTIONARY: &[&str] = &["bitrix/admin/", "bitrix/modules/", "bitrix/.settings.php"];
const WORDPRESS_DICTIONARY: &[&str] = &["wp-config.php", "wp-admin/", "xmlrpc.php"];
const JOOMLA_PHPBB_DICTIONARY: &[&str] = &["configuration.php", "config.php", "administrator/"];

enum TargetResponse {
    Open,       // 200 OK / 301 Redirect
    Protected,  // 403 Forbidden
    Missing,    // 404 Not Found
    WafBlocked, // 429 Too Many Requests / 503 / 403 глобальный бан контура
}

// ГЛАВНЫЙ ДИСПЕТЧЕР: Интеллектуальный адаптивный штурм периметра
pub async fn execute_deep_fuzzing(target: &str, issues: &mut Vec<SecurityIssue>) {
    println!("[*] Инициализация адаптивного Attack Chain Engine...");
    let addr = format!("{}:443", target);

    // ШАГ 1. Системная калибровка (Защита от ложных срабатываний / "Fake 200 OK")
    let fake_path = format!("failed_test_path_{}.html", generate_random_marker());
    let calibration = request_target_status(&addr, target, &fake_path).await;
    
    if let TargetResponse::Open = calibration {
        println!("[!] Предупреждение: Сервер использует 'Fake 200 OK' для всех страниц. Пассивный фаззинг путей ограничен.");
        return;
    }

    // ШАГ 2. Первичный OSINT и сборка динамического словаря под стек сайта
    let mut dynamic_dictionary: Vec<&str> = BASE_DICTIONARY.to_vec();
    let mut detected_cms = "Unknown";

    // Проверяем маркеры популярных систем
    for (cms_name, test_path, sub_dict) in [
        ("Bitrix", "bitrix/admin/", BITRIX_DICTIONARY),
        ("WordPress", "wp-login.php", WORDPRESS_DICTIONARY),
        ("Joomla/phpBB", "administrator/", JOOMLA_PHPBB_DICTIONARY)
    ] {
        if let TargetResponse::Open | TargetResponse::Protected = request_target_status(&addr, target, test_path).await {
            detected_cms = cms_name;
            dynamic_dictionary.extend_from_slice(sub_dict);
            break;
        }
    }
    println!("[+] Анализ контура завершен. Обнаруженный стек: [{}]. Размер словаря: {} объектов.", detected_cms, dynamic_dictionary.len());

    // ШАГ 3. Адаптивный перебор с защитой от блокировок
    for path in dynamic_dictionary {
        match request_target_status(&addr, target, path).await {
            TargetResponse::Open => {
                println!("[CRITICAL] Прямой пробой контура! Открытый объект: /{}", path);
                issues.push(create_exploit_chain_issue(path, "Critical"));
            }
            TargetResponse::Protected => {
                println!("[HIGH] Защищенная зона обнаружена (Потенциальный вектор брута): /{}", path);
                issues.push(create_exploit_chain_issue(path, "High"));
            }
            TargetResponse::WafBlocked => {
                println!("[!] Обнаружена активная защита WAF / Rate-Limiter! Замедление потока...");
                tokio::time::sleep(Duration::from_secs(3)).await; // Интеллектуальная пауза, чтобы обойти бан
            }
            TargetResponse::Missing => {}
        }
        // Легкая маскировочная пауза между запросами (Защита от триггеров простых IDS)
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

// НИЗКОУРОВНЕВЫЙ ТРАНСПОРТ (Имитирует поведение легитимного браузера)
async fn request_target_status(addr: &str, target: &str, path: &str) -> TargetResponse {
    let Ok(Ok(mut stream)) = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await else {
        return TargetResponse::Missing;
    };

    // Формируем полностью легитимный HEAD запрос с User-Agent, чтобы обмануть простейшие WAF-фильтры
    let req = format!(
        "HEAD /{} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Connection: close\r\n\r\n",
        path, target
    );
    
    if stream.write_all(req.as_bytes()).await.is_err() { return TargetResponse::Missing; }
    
    let mut response = String::new();
    if stream.read_to_string(&mut response).await.is_err() { return TargetResponse::Missing; }
    
    if response.contains("HTTP/1.1 200") || response.contains("HTTP/1.1 301") || response.contains("HTTP/1.1 302") {
        TargetResponse::Open
    } else if response.contains("HTTP/1.1 403") {
        TargetResponse::Protected
    } else if response.contains("HTTP/1.1 429") || response.contains("HTTP/1.1 503") || response.contains("Cloudflare") {
        TargetResponse::WafBlocked
    } else {
        TargetResponse::Missing
    }
}

// УНИВЕРСАЛЬНЫЙ ШАБЛОНИЗАТОР СЦЕНАРИЕВ ВЗЛОМА
fn create_exploit_chain_issue(path: &str, mode: &str) -> SecurityIssue {
    if mode == "Critical" {
        SecurityIssue {
            severity: "Critical".into(),
            title: format!("Прямая утечка данных контура: Открытый файл /{}", path),
            description: format!(
                "В ходе интеллектуального фаззинга обнаружен критический объект /{}, доступный без авторизации.\
                \n\n[☠️ СЦЕНАРИЙ ХАКЕРСКОЙ АТАКИ (Exploit Chain)]:\n\
                1. Злоумышленник скачивает этот файл напрямую в обход систем защиты периметра.\n\
                2. Извлекает из него чувствительные переменные среды (пароли СУБД, секретные ключи авторизации сессий, токены интеграций).\n\
                3. Реализует вектор полного захвата контроля над сервером (RCE) или компрометирует базу данных пользователей.", 
                path
            ),
            remediation: format!("Немедленно удалите объект /{} из публичного каталога сервера или перенастройте правила видимости.", path),
        }
    } else {
        SecurityIssue {
            severity: "High".into(),
            title: format!("Раскрытие критической инфраструктуры: /{}", path),
            description: format!(
                "Веб-сервер подтвердил существование скрытого каталога или панели управления /{} (код 403 Forbidden).\
                \n\n[☠️ СЦЕНАРИЙ ХАКЕРСКОЙ АТАКИ (Exploit Chain)]:\n\
                1. Хакер фиксирует точную архитектуру и версию CMS/ПО по косвенным признакам.\n\
                2. Использует технику Header Injection (подмена заголовков X-Forwarded-For) для попытки обхода 403-й ошибки локально.\n\
                3. Запускает таргетированный перебор скомпрометированных паролей администраторов.", 
                path
            ),
            remediation: "Скройте факт существования директории, настроив веб-сервер на возврат кода 404 Not Found для неавторизованных внешних IP-адресов.".to_string(),
        }
    }
}

fn generate_random_marker() -> u16 {
    // Простейший генератор случайного числа для калибровочного пути
    let ptr = &fake_path_marker as *const _ as usize;
    (ptr & 0xFFFF) as u16
}
static fake_path_marker: u8 = 0;
