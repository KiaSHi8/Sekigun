# Sekigun 🚀

### 🇷🇺 Описание проекта (Russian)

**Sekigun** — инструмент для автоматизированного анализа безопасности веб-ресурсов, написанный на языке Rust.
Сканер интегрирован с локальной языковой моделью (Phi-3) для интеллектуального анализа ответов сервера, что позволяет снизить количество ложных срабатываний при 
поиске уязвимостей.

#### Основные характеристики:
* **Высокая производительность:** Эффективное использование многопоточности и памяти благодаря архитектуре Rust.
* **Локальный ИИ:** Анализ данных происходит полностью на локальной машине через формат `.gguf` без отправки запросов на внешние API.
* **Безопасность данных:** Отчеты о сканировании (HTML/TXT) сохраняются строго локально и автоматически игнорируются системой контроля версий Git.

#### ⚠️ ДИСКЛЕЙМЕР / ОТКАЗ ОТ ОТВЕТСТВЕННОСТИ
> Данный инструмент разработан исключительно для образовательных целей и легального аудита безопасности (Pentesting) с предварительного согласия владельцев целевых ресурсов.
>  Автор проекта не несет ответственности за любой возможный ущерб, неправомерное использование софта или нарушение законодательства третьими лицами.

#### Инструкция по запуску:
1. Создайте папку `models` в корневой директории проекта.
2. Разместите скачанную модель **Phi-3 Mini 4K** в формате `.gguf` внутри этой папки:
   ```text
   Sekigun/
   └── models/
       └── phi3-mini-4k.gguf
   ```
3. Сборка и запуск проекта:
   ```bash
   cargo run --release -- --target <URL_ЦЕЛИ>
   ```

---

### 🇺🇸 Project Overview (English)

**Sekigun** is an automated web vulnerability scanner built with Rust. It features integration with a local AI model (Phi-3) to analyze server responses, 
enabling more accurate detection of security flaws and reducing false positives.

#### Key Features:
* **Rust Performance:** Memory-safe, high-speed concurrent scanning with low resource usage.
* **Local AI Execution:** Utilizes an LLM via `.gguf` running entirely on your machine to ensure complete data privacy.
* **Privacy First:** Scan logs and HTML reports stay strictly on your local computer and are blocked by `.gitignore`.

#### ⚠️ LEGAL DISCLAIMER
> This tool is provided strictly for educational purposes and authorized security auditing (penetration testing) with the explicit consent of the target's owner.
>  The author accepts no liability and is not responsible for any misuse, damage, or illegal activities caused by this program.

#### Quick Start:
1. Create a `models` folder in the root of the project.
2. Download the **Phi-3 Mini 4K** model in `.gguf` format and place it inside:
   ```text
   Sekigun/
   └── models/
       └── phi3-mini-4k.gguf
   ```
3. Build and execute:
   ```bash
   cargo run --release -- --target <TARGET_URL>
   ```

---
📄 **License:** This project is licensed under the terms specified in the [LICENSE](LICENSE) file.




---

### 💬 🇷🇺 ОБРАТНАЯ СВЯЗЬ ДЛЯ СВОИХ (Crypto-Anarchy / Hacktivism)
> Если этот сканер помог вам в реальном деле на передовой или вы вскрыли им что-то по-настоящему крупное — не молчите!
>  Стучитесь мне в личку. Интересно пообщаться, разобрать кейсы, обменяться опытом и обсудить, как софт показал себя в боевых условиях.
> Полная конфиденциальность гарантирована. Шифропанки и анархисты всех стран, WELCOME! 

### 💬 🇺🇸 FEEDBACK FOR THE UNDERGROUND (Crypto-Anarchy / Hacktivism)
> If this scanner actually helped you out in a real-world operation or assisted in cracking open a major target — drop a message in my DMs.
> Let’s talk shop, review the logs, and discuss how the tool performs under real pressure.
>  Total anonymity and privacy guaranteed. Cypherpunks write code, hackers test it. 
