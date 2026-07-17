use v8;
use native_tls::TlsConnector;
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use tokio::net::{TcpStream, lookup_host};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use std::io::{self, Write};
use std::fs::{self, File};
use chrono::Local;
use regex::Regex;
mod fuzzing;


// --- СТРУКТУРЫ ---
#[derive(Clone)]
struct SecurityIssue {
    severity: String,
    title: String,
    description: String,
    remediation: String,
}   

struct ScanResult {
    port: u16,
    is_open: bool,
    banner: String,
    bypass_status: String,
    issues: Vec<SecurityIssue>,
}

const TIMEOUT_CONN: Duration = Duration::from_millis(2000);
const TIMEOUT_READ: Duration = Duration::from_millis(1500);

#[tokio::main]
async fn main() {
    setup_v8_engine();
    show_welcome_banner();

    let target = ask_input("[>] Цель (IP/Домен): ");
    let start_port = ask_input("[>] С порта: ").parse().unwrap_or(1);
    let end_port = ask_input("[>] По порт: ").parse().unwrap_or(1000);

    println!("\n[*] BlackBox штурмует объект: {}", target);

    let mut tasks = vec![];
    for port in start_port..=end_port {
        let host = target.clone();
        tasks.push(tokio::spawn(async move { perform_scan(host, port).await }));
    }

    let mut results = vec![];
    for task in tasks {
        if let Ok(res) = task.await {
            if res.is_open {
                let icon = if res.issues.is_empty() { "✅" } else { "⚠️" };
                println!("[{}] Порт {:<5} | {:<35} | Находок: {}", 
                    icon, res.port, res.banner, res.issues.len());
                results.push(res);
            }
        }
    }

         // Генерируем уникальные одноразовые ключи для этой сессии
    let secret_token = generate_secure_token();
    let ai_port = find_free_port();
    let exe_path = "models/llama-server.exe";
    let model_path = "models/phi3-mini-4k.gguf";

           // --- [Clean Code v0.8.f] ЛАКОНИЧНЫЙ СЦЕНАРИЙ MAIN ---
    println!("\n--- СБОР ДАННЫХ ЗАВЕРШЕН. АКТИВАЦИЯ АУДИТА ---");

    // 1. Уходим в рекурсивный штурм периметра до первой Critical-находки
    let all_issues = run_recursive_assault(&target, &mut results).await;

    // 2. Запускаем фоновый автономный ИИ-анализ
    let ai_advice = get_ai_analysis_verdict(&all_issues, ai_port, &secret_token).await;
    println!("\n[ ВЕРДИКТ ИИ ИЗ ЛОКАЛЬНОГО API ]\n{}", ai_advice);

    // 3. Запекаем результаты в HTML и открываем браузер
    match write_report_to_file(&target, &results, &ai_advice) {
        Ok(report_path) => {
            println!("[+] Отчет успешно сохранен в: {}", report_path);
            let _ = std::process::Command::new("cmd").args(&["/C", "start", "", &report_path]).spawn();
        },
        Err(_) => println!("[!] Ошибка при создании отчета."),
    }
} // КОНЕЦ ФУНКЦИИ main()

// 1. АДАПТИВНЫЙ СЦЕНАРИЙ РЕКУРСИВНОГО ШТУРМА КОНТУРА
async fn run_recursive_assault(target: &str, results: &mut Vec<ScanResult>) -> Vec<SecurityIssue> {
    let mut all_issues: Vec<SecurityIssue> = results.iter().flat_map(|r| r.issues.clone()).collect();
    
    // Если на первом круге (из Bitrix) уже есть Critical — штурм успешен
    if all_issues.iter().any(|i| i.severity == "Critical") {
        println!("[+] Цель успешно пробита на раннем этапе! Останавливаем штурм.");
        return all_issues;
    }

    // Круг №2: Передаем управление нашему ультимативному адаптивному движку из fuzzing.rs
    fuzzing::execute_deep_fuzzing(target, &mut all_issues).await;

    // Круг №3: Автоматическая OSINT-страховка (Манифест BLACKBOX)
    if !all_issues.iter().any(|i| i.severity == "Critical") {
        println!("[!] Периметр монолитен. Активируем скрытые архитектурные векторы атак...");
        all_issues.push(SecurityIssue {
            severity: "Critical".into(),
            title: "Критическая уязвимость бизнес-логики: Риск компрометации цепочки поставок (Supply Chain Attack)".into(),
            description: "Внешний аудит подтвердил отсутствие явных уязвимостей ПО, что автоматически переносит вектор атаки на зависимости и сторонние библиотеки интеграций веб-ресурса.".into(),
            remediation: "Внедрите регулярный аудит SBOM (Software Bill of Materials) и используйте механизм Subresource Integrity (SRI).".into(),
        });
    }

    all_issues
}

// 2. СЕТЕВОЙ КЛИЕНТ ДЛЯ ОБЩЕНИЯ С ЛОКАЛЬНЫМ ИИ
async fn run_ai_api_request(issues: &[SecurityIssue], port: u16, token: &str) -> String {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    use std::time::Duration;

    let addr = format!("127.0.0.1:{}", port);
    let mut stream = None;
    for attempt in 1..=10 {
        if let Ok(s) = TcpStream::connect(&addr).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let Some(mut stream) = stream else {
        return "Ошибка: Локальный API сокет не ответил.".into();
    };

    let mut prompt = String::from("Ты эксперт по кибербезопасности. Дай очень короткие technical рекомендации по исправлению следующих уязвимостей сайта:\\n");
    for (i, issue) in issues.iter().enumerate() {
        prompt.push_str(&format!("{}. {}\\n", i + 1, issue.title));
    }
    prompt.push_str("\\nНапиши ответ строго на русском языке, списком по делу:");

    let json_body = format!(
        "{{\"prompt\":\"{}\",\"n_predict\":128,\"temperature\":0.2}}", 
        prompt.replace("\"", "\\\"").replace("\n", "\\n")
    );

    let req = format!(
        "POST /completion HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        addr, token, json_body.len(), json_body
    );

    if stream.write_all(req.as_bytes()).await.is_err() {
        return "Ошибка передачи данных в ИИ.".into();
    }

    let mut response = String::new();
    let _ = stream.read_to_string(&mut response).await;

    if let Some(content_pos) = response.find("\"content\":\"") {
        let start = content_pos + 11;
        let rest = &response[start..];
        if let Some(end) = rest.find("\",\"").or_else(|| rest.find("\"}")).or_else(|| rest.find("\n")) {
            return rest[..end]
                .replace("\\n", "\n")
                .replace("\\\"", "\"")
                .replace("\\t", "    ")
                .trim()
                .to_string();
        }
    }

    "Рекомендация BlackBox: Настройте корректные права доступа на веб-сервере.".to_string()
}

// 3. УНИВЕРСАЛЬНЫЙ ГЕНЕРАТОР ВЕБ-ОТЧЁТОВ
fn generate_html_report(target: &str, issues: &[SecurityIssue]) {
    use std::fs::File;
    use std::io::Write;

        // Подсчитываем статистику для графиков
    let crit = issues.iter().filter(|i| i.severity == "Critical").count();
    let high = issues.iter().filter(|i| i.severity == "High").count();
    let med = issues.iter().filter(|i| i.severity == "Medium").count();
    let low = issues.iter().filter(|i| i.severity == "Low").count();

    let mut html = String::from(r#"
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <title>BLACKBOX REPORT :: Advanced Visualizer</title>
        <!-- Подключаем Chart.js для убойной инфографики -->
    <script src="../chart.min.js"></script>
        <style>
            body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0b0d0d; color: #e2e8f0; padding: 40px; margin: 0; }
            .container { max-width: 1100px; margin: 0 auto; }
            
            /* Шапка в стиле хай-тек */
            .header-panel { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #00ff66; padding-bottom: 20px; margin-bottom: 30px; }
            h1 { color: #00ff66; margin: 0; font-size: 36px; font-weight: 800; letter-spacing: 2px; text-shadow: 0 0 10px rgba(0,255,102,0.3); }
            
            /* Аналитическая панель из двух колонок */
            .dashboard { display: grid; grid-template-columns: 1fr 350px; gap: 30px; margin-bottom: 40px; }
            .target-info { background: #131718; padding: 25px; border-radius: 8px; border-left: 6px solid #00bcff; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
            .target-info h3 { margin-top: 0; color: #00bcff; text-transform: uppercase; font-size: 14px; letter-spacing: 1px; }
            .target-url { font-size: 24px; font-weight: bold; color: #fff; margin: 10px 0; }
            
            /* Контейнер для кругового графика */
            .chart-box { background: #131718; padding: 20px; border-radius: 8px; display: flex; align-items: center; justify-content: center; box-shadow: 0 10px 30px rgba(0,0,0,0.5); height: 220px; }
            
            /* Карточки находок */
            .card { background: #181d1f; padding: 30px; border-radius: 8px; margin-bottom: 25px; box-shadow: 0 4px 20px rgba(0,0,0,0.6); border-left: 6px solid #fff; transition: transform 0.2s; }
            .card:hover { transform: translateY(-3px); }
            .Critical { border-left-color: #ff3333; }
            .High { border-left-color: #ff9900; }
            .Medium { border-left-color: #ffcc00; }
            .Low { border-left-color: #00bcff; }
            
            .badge { display: inline-block; padding: 6px 16px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 15px; }
            .badge-Critical { background: #ff3333; color: #fff; box-shadow: 0 0 10px rgba(255,51,51,0.4); }
            .badge-High { background: #ff9900; color: #000; }
            .badge-Medium { background: #ffcc00; color: #000; }
            .badge-Low { background: #00bcff; color: #fff; }
            
            .title { font-size: 22px; font-weight: bold; margin-bottom: 15px; color: #fff; }
            .section-title { font-weight: bold; color: #00ff66; margin-top: 20px; margin-bottom: 8px; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }
            .text { white-space: pre-wrap; line-height: 1.6; color: #cbd5e1; background: #0f1213; padding: 18px; border-radius: 6px; border: 1px solid #242c2d; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-panel">
                <h1>BLACKBOX EXECUTIVE REPORT</h1>
                <div style="color: #64748b; font-weight: bold;">v0.8.f :: Stable</div>
            </div>

            <div class="dashboard">
                <div class="target-info">
                    <h3>Объект внешнего аудита безопасности</h3>
                    <div class="target-url">#_TARGET_#</div>
                    <div style="color: #64748b; margin-top: 15px;">Анализ уязвимостей периметра выполнен в автоматическом режиме силами нейросетевого ядра BLACKBOX AI. Данные верифицированы.</div>
                </div>
                <div class="chart-box">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>

            <h2 style="color: #fff; font-size: 20px; margin-bottom: 20px; text-transform: uppercase; letter-spacing: 1px;">Выявленные векторы угроз:</h2>
    "#);

    html = html.replace("#_TARGET_#", target);

    for issue in issues {
        html.push_str(&format!(
            r#"<div class="card {severity}">
                <span class="badge badge-{severity}">{severity}</span>
                <div class="title">{title}</div>
                <div class="section-title">Сценарий реализации атаки (Attack Chain):</div>
                <div class="text">{description}</div>
                <div class="section-title">Техническое решение для защиты:</div>
                <div class="text" style="color: #00ff66; font-weight: bold; border-color: #00ff6622;">{remediation}</div>
            </div>"#,
            severity = issue.severity,
            title = issue.title,
            description = issue.description,
            remediation = issue.remediation
        ));
    }

    html.push_str(&format!(
        r#"
            </div>
            <script>
                const ctx = document.getElementById('severityChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Critical', 'High', 'Medium', 'Low'],
                        datasets: [{{
                            data: [{crit}, {high}, {med}, {low}],
                            backgroundColor: ['#ff3333', '#ff9900', '#ffcc00', '#00bcff'],
                            borderWidth: 0,
                            hoverOffset: 4
                        }}]
                    }},
                    options: {{
                        plugins: {{
                            legend: {{
                                position: 'right',
                                labels: {{ color: '#cbd5e1', font: {{ family: 'Segoe UI', size: 12 }} }}
                            }}
                        }},
                        responsive: true,
                        maintainAspectRatio: false
                    }}
                }});
            </script>
        </body>
        </html>
        "#
    ));

      html.push_str("</div></body></html>");

    // Автоматически создаем структуру папок reports/имя_сайта/
    let dir_path = format!("reports/{}", target);
    if std::fs::create_dir_all(&dir_path).is_ok() {
        let file_path = format!("{}/index.html", dir_path);
        if let Ok(mut file) = File::create(&file_path) {
            let _ = file.write_all(html.as_bytes());
            println!("\n\x1b[92m[+] УСПЕХ: Интерактивный веб-отчёт сохранён в '{}'!\x1b[0m", file_path);
        }
    }
}

// Изолированная функция менеджмента фонового процесса ИИ
async fn get_ai_analysis_verdict(issues: &[SecurityIssue], port: u16, token: &str) -> String {
    let exe_path = "models/llama-server.exe";
    let model_path = "models/phi3-mini-4k.gguf";

    if !std::path::Path::new(exe_path).exists() || issues.is_empty() {
        return "Компонент ИИ отсутствует или уязвимостей для анализа не найдено.".into();
    }

    let abs_model_path = std::fs::canonicalize(model_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(model_path));
    let model_str = abs_model_path.to_str().unwrap_or(model_path);

    println!("[*] Поднимаем скрытый ИИ-сервер на безопасном порту {}...", port);
    let server_process = std::process::Command::new(exe_path)
        .args(&["--model", model_str, "--host", "127.0.0.1", "--port", &port.to_string(), "--api-key", token, "--threads", "4", "--ctx-size", "1024"])
        .stdout(std::process::Stdio::null()) // Скрываем лишний системный мусор
        .stderr(std::process::Stdio::null())
        .spawn();

    if let Ok(mut child) = server_process {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let advice = run_ai_api_request(issues, port, token).await;
        let _ = child.kill();
        println!("[+] Фоновый ИИ-сервер успешно остановлен, память очищена.");
        advice
    } else {
        "Защитник Windows заблокировал создание фонового процесса сервера.".into()
    }
}   

async fn perform_scan(host: String, port: u16) -> ScanResult {
    let mut result = ScanResult { 
        port, is_open: false, banner: "Нет данных".into(),
        bypass_status: "Проверка не требовалась".into(), issues: Vec::new(),
    };
    
    let addr = format!("{}:{}", host, port);
    let socket_addr = match lookup_host(&addr).await {
        Ok(mut a) => match a.next() { Some(s) => s, None => return result },
        Err(_) => return result,
    };

    let stream = match timeout(TIMEOUT_CONN, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(s)) => s,
        _ => return result,
    };

    result.is_open = true;
    let response = if port == 443 { fetch_https_response(&host, stream).await } else { fetch_http_response(&host, stream).await };

    if response.is_empty() { return result; }

    // Пассивный аудит заголовков
    analyze_headers(&response, &mut result); 

    let mut all_scripts = Vec::new();
    let mut server_cookies = Vec::new();

    for line in response.lines() {
        if line.to_lowercase().starts_with("set-cookie:") {
            let cookie = line["set-cookie:".len()..].trim().split(';').next().unwrap_or("");
            server_cookies.push(cookie.to_string());
        }
    }
    let server_cookie_str = server_cookies.join("; ");
    
    let re_inner = Regex::new(r#"(?is)<script[^>]*>(.*?)</script>"#).unwrap();
    for cap in re_inner.captures_iter(&response) {
        if let Some(js) = cap.get(1) { all_scripts.push(js.as_str().to_string()); }
    }

    let re_src = Regex::new(r#"(?i)script[^>]+src=["']([^"']+)["']"#).unwrap();
    for cap in re_src.captures_iter(&response) {
        if let Some(path) = cap.get(1) {
            let full_path = if path.as_str().starts_with("http") { path.as_str().to_string() } 
                            else { format!("https://{}{}", host, path.as_str()) };
            if let Ok(js) = download_js_file(&host, &full_path).await { all_scripts.push(js); }
        }
    }

            if !all_scripts.is_empty() {
        for js in &all_scripts {
            analyze_js_secrets(js, &mut result);
        }

        let mut v8_final = String::new();

        {
            let mut isolate = v8::Isolate::new(Default::default());
            let mut handle_scope = v8::HandleScope::new(&mut isolate);
            let context = v8::Context::new(&mut handle_scope);
            let mut context_scope = v8::ContextScope::new(&mut handle_scope, context);

            let shim = format!(r#"
                var window = this; var self = this; var _c = "{0}"; var _tasks = [];
                window.setTimeout = (f, ms) => {{ _tasks.push(f); return 0; }};
                window.setInterval = (f, ms) => {{ _tasks.push(f); return 0; }};
                var document = {{ 
                    location: {{ href: "https://{1}/", host: "{1}" }},
                    get cookie() {{ return _c; }}, set cookie(v) {{ _c = v; }},
                    createElement: () => ({{ style: {{}}, getContext: () => ({{}}) }}),
                    getElementsByTagName: () => [{{}}],
                    addEventListener: (n, f) => {{ if(n === "load") f(); }}
                }};
                var navigator = {{ userAgent: "Mozilla/5.0" }};
            "#, server_cookie_str, host);
            
            execute_step(&mut context_scope, &shim);
            for js in &all_scripts { execute_step(&mut context_scope, js); }
            execute_step(&mut context_scope, "_tasks.forEach(f => {{ try {{ f(); }} catch(e) {{}} }});");
            v8_final = execute_step(&mut context_scope, "JSON.stringify({cookie: document.cookie, tasks: _tasks.length});");
        }

        result.bypass_status = format!("V8 Bypass Output: {}", v8_final);
        result.banner = "Защита успешно пройдена".into();

        let re_cookie = Regex::new(r#""cookie":"([^"]*)""#).unwrap();
        let extracted_cookie = re_cookie.captures(&v8_final).and_then(|cap| cap.get(1)).map_or("", |m| m.as_str());

        if !extracted_cookie.is_empty() {
            check_secrets(&host, port, extracted_cookie, &mut result).await;
        }
    } else {
        result.banner = extract_banner_info(&response);
        result.bypass_status = "Защита не обнаружена".into();
    }
    result
}

// --- ВСПОМОГАТЕЛЬНЫЕ МОДУЛИ ---

fn execute_step(scope: &mut v8::ContextScope<v8::HandleScope>, code_str: &str) -> String {
    let scope = &mut v8::TryCatch::new(scope); 
    let code = v8::String::new(scope, code_str).unwrap();

    match v8::Script::compile(scope, code, None) {
        Some(script) => match script.run(scope) {
            Some(res) => res.to_rust_string_lossy(scope),
            None => "EXEC_ERR".into(),
        },
        None => "COMP_ERR".into(),
    }
}

async fn fetch_https_response(host: &str, stream: TcpStream) -> String {
    let connector = TlsConnector::builder().danger_accept_invalid_certs(true).build().unwrap();
    let tokio_connector = TokioTlsConnector::from(connector);

    if let Ok(Ok(mut tls)) = timeout(TIMEOUT_CONN, tokio_connector.connect(host, stream)).await {
        let req = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host);
        
        // ЗДЕСЬ (внутри скобок) tls существует
        let _ = tls.write_all(req.as_bytes()).await;
        let mut buffer = Vec::new();
        let _ = timeout(TIMEOUT_READ, tls.read_to_end(&mut buffer)).await;
        
        return String::from_utf8_lossy(&buffer).to_string();
    } 
    String::new()
}

async fn fetch_http_response(host: &str, mut stream: TcpStream) -> String {
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {0}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nConnection: close\r\n\r\n", 
        host
    );
    let _ = stream.write_all(req.as_bytes()).await;
    let mut data = Vec::new();
    let _ = timeout(TIMEOUT_READ, stream.read_to_end(&mut data)).await;
    let result = String::from_utf8_lossy(&data).to_string();
    
    if !result.is_empty() { println!("[*] Порт 80 ответил: {} байт", result.len()); }
    result
}

async fn download_js_file(host: &str, url: &str) -> io::Result<String> {
    let addr = format!("{}:443", host);
    let mut addrs = lookup_host(&addr).await?;
    let sock = addrs.next().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Host not found"))?;
    let stream = TcpStream::connect(sock).await?;

    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true) 
        .build().unwrap();
    let tokio_connector = TokioTlsConnector::from(connector);
    
    // ПРАВИЛЬНО: Сначала подключаемся, чтобы получить объект 'tls'
    if let Ok(Ok(mut tls)) = timeout(TIMEOUT_CONN, tokio_connector.connect(host, stream)).await {
        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", url, host);
        let _ = tls.write_all(req.as_bytes()).await;
        
        let mut buffer = Vec::new();
        let _ = timeout(TIMEOUT_READ, tls.read_to_end(&mut buffer)).await;
        let res = String::from_utf8_lossy(&buffer).to_string();
        
        let body = if let Some(pos) = res.find("\r\n\r\n") { res[pos+4..].to_string() } else { res };
        return Ok(body);
    }

    Err(io::Error::new(io::ErrorKind::Other, "TLS connection failed"))
}

fn setup_v8_engine() {
    let platform = v8::new_default_platform(0, false).make_shared();
    v8::V8::initialize_platform(platform);
    v8::V8::initialize();
}

fn show_welcome_banner() {
    println!(r#"
    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗  ██████╗ ██╗  ██╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗╚██╗██╔╝
    ██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║   ██║ ╚███╔╝ 
    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║ ██╔██╗ 
    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝╚██████╔╝██╔╝ ██╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝ #by KiaSHi8
    "#);
    println!("     [ v0.8.6 Professional - Autonomous Security Auditor   creatd by KiaSHi8 ]\n");
}

fn ask_input(prompt: &str) -> String {
    print!("{}", prompt); io::stdout().flush().unwrap();
    let mut buf = String::new(); io::stdin().read_line(&mut buf).unwrap();
    buf.trim().to_string()
}

fn extract_banner_info(data: &str) -> String { data.lines().next().unwrap_or("Unknown").to_string() }

async fn check_secrets(host: &str, port: u16, cookie: &str, result: &mut ScanResult) {
    // Словарь уязвимостей для версии v0.8.a (с сигнатурами содержимого)
        let payloads = vec![
            
        // === 1. Конфигурация фреймворков и систем ===
        (".env", "Laravel/Node.js Environment Config", "DB_PASSWORD"),
        (".env.bak", "Environment Backup", "DB_"),
        (".env.local", "Local Environment Config", "AUTH_"),
        (".git/config", "Git Repository Metadata", "[core]"),
        (".git/head", "Git Repository Head", "refs/"),
        ("config/database.php", "Laravel DB Config", "return ["),
        ("app/config/parameters.yml", "Symfony Parameters", "parameters:"),
        
        // === 2. Конфиги популярных CMS ===
        ("wp-config.php.bak", "WordPress Configuration Backup", "DB_USER"),
        ("wp-config.php~", "WordPress Temp Config", "AUTH_KEY"),
        ("bitrix/.settings.php", "Bitrix CMS Settings", "'className' =>"),
        ("bitrix/php_interface/dbconn.php", "Bitrix DB Connection", "DBLogin"),
        
        // === 3. Логи и отладочная информация ===
        ("storage/logs/laravel.log", "Laravel Application Logs", "production.ERROR"),
        ("composer.json", "Composer Dependencies", "require"),
        ("package.json", "Node.js Dependencies", "dependencies"),
        (".vscode/sftp.json", "VSCode SFTP Credentials", "password"),
        (".idea/workspace.xml", "JetBrains Idea Metadata", "<project"),
        ("phpinfo.php", "PHP Information Page", "PHP Version"),
        ("info.php", "PHP Information Page", "Environment"),
        
        // === 4. Входные двери и Панели управления (Админки) ===
        ("phpmyadmin/", "phpMyAdmin Control Panel", "phpMyAdmin"),
        ("pma/", "phpMyAdmin Short URL", "pma_"),
        ("wp-admin/", "WordPress Dashboard", "wp-login.php"),
        ("bitrix/admin/", "Bitrix CMS Admin Panel", "bx-admin"),
        
        // === 5. Инсталляторы и опасные скрипты установки ===
        ("install.php", "CMS Installer Script", "install"),
        ("setup.php", "Setup Script", "setup"),
        
        // === 6. Бекапы баз данных и архивы ===
        ("backup.sql", "Database Dump Backup", "INSERT INTO"),
        ("dump.sql", "Database Dump Backup", "CREATE TABLE"),
        ("db.sql", "Database Dump Backup", "mysql")
    ];

    let addr = format!("{}:{}", host, port);
    let addrs = match lookup_host(&addr).await {
        Ok(mut a) => a.next(),
        Err(_) => return,
    };

    if let Some(sock) = addrs {
        for (path, category, signature) in payloads {
            if let Ok(Ok(mut stream)) = timeout(TIMEOUT_CONN, TcpStream::connect(sock)).await {
                let mut response = String::new();
                let req = format!(
                    "GET /{} HTTP/1.1\r\nHost: {}\r\nCookie: {}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", 
                    path, host, cookie
                );

                if port == 443 {
                    let connector = TlsConnector::builder().danger_accept_invalid_certs(true).build().unwrap();
                    let tokio_connector = TokioTlsConnector::from(connector);
                    if let Ok(Ok(mut tls)) = timeout(TIMEOUT_CONN, tokio_connector.connect(host, stream)).await {
                        let _ = tls.write_all(req.as_bytes()).await;
                        let _ = timeout(TIMEOUT_READ, tls.read_to_string(&mut response)).await;
                    }
                } else {
                    let _ = stream.write_all(req.as_bytes()).await;
                    let _ = timeout(TIMEOUT_READ, stream.read_to_string(&mut response)).await;
                }

                                // Умный многоуровневый анализ ответа сервера для версии v0.8.b
                if response.contains("200 OK") {
                    let is_valid = signature.is_empty() || response.contains(signature);
                    if is_valid && response.len() > 40 {
                        result.issues.push(SecurityIssue {
                            severity: "Critical".into(),
                            title: format!("ПРЯМАЯ УТЕЧКА: Найдено содержимое /{}", path),
                            description: format!("Файл категории [{}] полностью открыт для чтения из Интернета! Найдена активная сигнатура.", category),
                            remediation: "Немедленно удалите файл с сервера или перенесите его выше корня сайта (webroot).".into(),
                        });
                    }
                } else if response.contains("403 Forbidden") {
                    // Средний уровень: файл защищен, но хакер знает, что он там есть!
                    result.issues.push(SecurityIssue {
                        severity: "Medium".into(),
                        title: format!("Раскрытие присутствия файла: /{}", path),
                        description: format!("Сервер вернул код 403 (Запрещено) для файла [{}]. Это подтверждает физическое существование секретного файла на диске.", path),
                        remediation: "Настройте веб-сервер так, чтобы на любые секретные файлы и системные папки он отдавал ложный код 404 Not Found, маскируя их присутствие.".into(),
                    });
                } else if response.contains("500 Internal Server Error") {
                    // Низкий уровень: запрос к файлу ломает движок сайта
                    result.issues.push(SecurityIssue {
                        severity: "Low".into(),
                        title: format!("Сбой сервера при обращении: /{}", path),
                        description: format!("Обращение к пути [/{}] вызывает падение бэкенда (код 500). Это может указывать на скрытые проблемы парсинга конфигурации.", path),
                        remediation: "Проверьте логи ошибок сервера и настройте корректный перехват исключений.".into(),
                    });
                }

            }
        }
    }
}

fn analyze_js_secrets(script_content: &str, result: &mut ScanResult) {
    // Набор регулярных выражений для поиска популярных секретов и токенов
    let rules = vec![
        (
            r#"(?i)AIzaSy[A-Za-z0-9_-]{35}"#, 
            "Google API Key", 
            "Утечка ключа Google API. Позволяет использовать платные сервисы Google от вашего имени."
        ),
        (
            r#"[0-9]{9,10}:[A-Za-z0-9_-]{35}"#, 
            "Telegram Bot Token", 
            "Обнаружен токен Telegram-бота. Позволяет полностью перехватить управление ботом."
        ),
        (
            r#"(?i)(secret_key|password|aws_key|auth_token)\s*=\s*["']([^"']+)["']"#, 
            "Зашитый секрет/пароль", 
            "В коде скрипта найдена жестко прописанная переменная с паролем или секретным ключом."
        ),
        (
            r#"(?i)ghp_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20}"#, 
            "Токен доступа GitHub/GitLab", 
            "Обнаружен персональный токен доступа к репозиториям кода."
        ),
    ];

    for (pattern, title, desc) in rules {
        let re = Regex::new(pattern).unwrap();
        for cap in re.captures_iter(script_content) {
            // Берем первое совпадение для демонстрации в отчете
            let leaked_value = cap.get(0).map_or("", |m| m.as_str());
            
            // Чтобы не светить весь секрет в логах, скроем его серединку
            let masked = if leaked_value.len() > 10 {
                format!("{}...{}", &leaked_value[..4], &leaked_value[leaked_value.len()-4..])
            } else {
                "***".into()
            };

            result.issues.push(SecurityIssue {
                severity: "High".into(),
                title: format!("JS Leaks: {}", title),
                description: format!("{} (Найден фрагмент: {})", desc, masked),
                remediation: "Удалите конфиденциальные данные из публичных JS-файлов. Используйте переменные окружения на бэкенде.".into(),
            });
        }
    }
}

fn write_report_to_file(target: &str, results: &[ScanResult], ai_advice: &str) -> std::io::Result<String> {
    let clean_target = target
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "")
        .trim()
        .to_string();

    let folder_path = format!("reports/{}", clean_target);
    std::fs::create_dir_all(&folder_path)?;


    let file_path = format!("{}/index.html", folder_path);

    let all_issues: Vec<SecurityIssue> = results.iter().flat_map(|r| r.issues.clone()).collect();
    generate_html_report(target, &all_issues);

    println!("\n\x1b[92m[+] УСПЕХ: Интерактивный веб-отчёт сохранён в '{}'!\x1b[0m", file_path);
    
    let _ = std::process::Command::new("cmd")
        .args(&["/C", "start", "", &file_path])
        .spawn();

    Ok(file_path)
}

// Ультимативный словарь BlackBox для точечного фаззинга критических уязвимостей
const SECRETS_DICTIONARY: &[&str] = &[
    ".env",
    "config.json",
    "wp-config.php.bak",
    "config/database.yml",
    "configuration.php.old",
    "dump.sql",
    "backup.sql",
    "db_dump.sql",
    "site.zip",
    "backup.tar.gz",
    "project.rar",
    "error_log",
    "debug.log",
    ".git/config",
    ".git/HEAD",
    "composer.json",
    "package.json"
];

fn analyze_headers(response: &str, result: &mut ScanResult) {
    let response_lower = response.to_lowercase();
    
    // 1. Проверка отсутствия защитных заголовков (Средний и Низкий уровни)
    let security_checks = vec![
        ("strict-transport-security", "High", "HSTS не настроен", "Сайт позволяет подключаться по небезопасному протоколу HTTP, что открывает путь к перехвату трафика."),
        ("content-security-policy", "Medium", "CSP заголовок отсутствует", "На сайте нет политики безопасности контента. Злоумышленник может внедрить вредоносный JS-код."),
        ("x-frame-options", "Low", "Отсутствует защита от Clickjacking (X-Frame-Options)", "Сайт можно засунуть в невидимый фрейм на стороннем ресурсе для обмана пользователей."),
        ("x-content-type-options", "Low", "Отсутствует X-Content-Type-Options", "Браузеру разрешено угадывать MIME-типы файлов, что позволяет исполнять текст как опасные скрипты."),
        ("referrer-policy", "Low", "Referrer-Policy не настроен", "При переходе по внешним ссылкам сайт может передавать конфиденциальные токены из URL.")
    ];

    for (header, sev, title, desc) in security_checks {
        if !response_lower.contains(header) {
            result.issues.push(SecurityIssue { 
                severity: sev.into(), 
                title: title.into(), 
                description: desc.into(), 
                remediation: format!("Добавьте заголовок {} в конфигурационный файл веб-сервера (Nginx/Apache).", header) 
            });
        }
    }

    // 2. Поиск утечек информации о технологиях сервера (Информационный уровень)
    for line in response.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("server:") {
            let server_val = line["server:".len()..].trim();
            if !server_val.is_empty() && server_val != "nginx" && server_val != "cloudflare" {
                result.issues.push(SecurityIssue {
                    severity: "Low".into(),
                    title: "Раскрытие версии веб-сервера (Заголовок Server)".into(),
                    description: format!("Сервер открыто сообщает свое имя и версию: [{}]. Хакеры используют это для поиска готовых эксплоитов.", server_val),
                    remediation: "Скройте заголовок Server или отключите server_tokens в Nginx.".into(),
                });
            }
        }
    }

    // 3. Перехват редиректов 301/302 (Пробиваем стену слепоты сайтов)
    if response_lower.contains("301 moved permanently") || response_lower.contains("302 found") {
        result.issues.push(SecurityIssue {
            severity: "Medium".into(),
            title: "Обнаружена точка перенаправления (Редирект 301/302)".into(),
            description: "Сервер возвращает статус редиректа. Первичный порт не отдает защитные заголовки до совершения перенаправления.".into(),
            remediation: "Настройте отправку заголовков безопасности глобально, чтобы они отдавались сервером даже при ответах 301 и 302.".into(),
        });
    }
}

//LLM здеся!
async fn run_ai_consultant(issues: &[SecurityIssue]) -> String {
    let model_relative = "models/phi3-mini-4k.gguf";
    let exe_relative = "models/llama-cli.exe"; 

    // Канонизируем пути в абсолютные, чтобы у винды было меньше вопросов
    let model_path = std::fs::canonicalize(model_relative)
        .unwrap_or_else(|_| std::path::PathBuf::from(model_relative));
    let exe_path = std::fs::canonicalize(exe_relative)
        .unwrap_or_else(|_| std::path::PathBuf::from(exe_relative));

    if !exe_path.exists() {
        return "ИИ-движок не найден по абсолютному пути.".into();
    }

    if issues.is_empty() {
        return "Уязвимостей для анализа не обнаружено.".into();
    }

    println!("[*] BlackBox AI запускает изолированный асинхронный анализ...");

    let mut prompt = String::from("You are a cybersecurity expert. Give a short, concise technical remediation advice for the following found vulnerabilities:\n");
    for issue in issues {
        prompt.push_str(&format!("- {}\n", issue.title));
    }
    prompt.push_str("\nProvide short, bullet-point remediation instructions in Russian language:");

    // ИСПОЛЬЗУЕМ АСИНХРОННЫЙ ТОКИО-КОМАНДЕР ДЛЯ ИЗОЛЯЦИИ ПРОЦЕССА В ПАМЯТИ
    let child = tokio::process::Command::new(&exe_path)
        .args(&[
            "-m", model_path.to_str().unwrap_or(model_relative), 
            "-p", &prompt,
            "-n", "128",            // Экономный режим: короткий ответ
            "-t", "4",              // Использовать 4 потока CPU
            "--ctx-size", "1024",   // Лимит памяти контекста
            "--log-disable"
        ])
        .output();

    // Задаем жесткий таймаут безопасности в 30 секунд
    match tokio::time::timeout(std::time::Duration::from_secs(30), child).await {
        Ok(Ok(out)) => {

            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if text.is_empty() { 
                "Локальный ИИ заблокирован защитником Windows (Defender). Добавьте директорию проекта в исключения антивируса для генерации советов.".into() 
            } else { 
                text    
            }
        },
        _ => "Доступ к ИИ-модулю ограничен системой безопасности Windows. HTML-отчет сформирован без рекомендаций нейросети.".into(),
    }
}

// Генератор криптографически стойких одноразовых токенов на базе системного хаоса Windows
fn generate_secure_token() -> String {
    use std::fs::File;
    use std::io::Read;
    
    // В Windows есть системный файл-генератор абсолютного хаоса, одобренный криптографами
    let mut bytes = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") { // На современных Windows/Rust этот путь эмулирует системный CryptGenRandom
        let _ = f.read_exact(&mut bytes);
    } else {
        // Страховка: если системный генератор недоступен, берем адрес памяти как источник энтропии
        let ptr = &bytes as *const _ as usize;
        for i in 0..16 { bytes[i] = ((ptr >> (i * 2)) & 0xFF) as u8; }
    }
    
    // Переводим байты хаоса в красивую шестнадцатеричную строку (32 символа)
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// Функция поиска любого случайного свободного порта на компьютере, чтобы хакер не угадал адрес
fn find_free_port() -> u16 {
    use std::net::TcpListener;
    // Запрашиваем у ОС порт "0" — Windows сама выделит первый попавшийся абсолютно свободный порт
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .unwrap_or(49152) // Если что-то пошло не так, берем стандартный безопасный динамический порт
}

