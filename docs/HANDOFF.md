# NetScope — хендофф

Состояние на 22.10.2026. Для того, кто продолжит работу: что выпущено, что лежит в `main`
и ещё не выпущено, что копится к следующему релизу, неочевидные места в коде и как
собрать и проверить релиз.

## Где мы сейчас

- **Последний релиз: [v0.4.0](https://github.com/Sobolev5/netscope/releases/tag/v0.4.0)** (Latest).
  Файлы: `NetScope-Setup-0.4.0.exe` (~3,5 МБ), `NetScope-Setup-0.4.0-full.exe` (~250 МБ, с WebView2 и
  геобазами), `netscope-0.4.0-windows-x64.zip` (портативная версия), `SHA256SUMS.txt`.
- В 0.4.0: фильтры на всех вкладках, группировка точек на карте по городам, подписи карты без
  наложений, исправлены кракозябры в русском инсталляторе.
- У v0.3.0 на GitHub плашка «Superseded by 0.4.0»: его инсталляторы показывают битый русский
  текст. Файлы не удалены, чтобы не ломать ссылки.
- Проверки на момент хендоффа: `cargo clippy --all-targets` чистый, `cargo test --all-targets` — 322
  теста, e2e инсталлятора 0.4.0 на живой машине — 43/43 (см. ниже).

## В `main`, но ещё не в релизе

- `7bc586f` — таблица Хостов помещается в окно: 9 колонок вместо 12 (хопы под RTT, ↓/↑/доля в
  одной колонке «Трафик», «Где» обрезается с подсказкой, «маршрут / следить» — ссылки).
- Этот хендофф и `scripts/e2e-installer.ps1`.

Версия в `Cargo.toml` по-прежнему `0.4.0` — при следующем релизе поднять.

## Копится к следующему релизу

Известные ограничения и то, что не проверялось:

- Фильтры Хостов и Карты работают по хостам из снимка (самые активные), а не по всем, что видел
  сервер. Чтобы фильтровать все, нужен серверный фильтр хостов по образцу DNS (`f=`).
- CSV-экспорт хостов и процессов выгружает всё, без учёта фильтров.
- У хоста перечисляются максимум 8 программ (`HOST_PROCESSES` в `snapshot.rs`).
- Каждый запуск `netscope-app` переписывает регистрацию протокола `netscope:` в HKCU на свой exe:
  запуск из `target\` перехватывает клики по уведомлениям у установленной копии (`toast.rs`,
  `register`). Разработчику неудобно, пользователю не мешает.
- Не проверено на живой системе: что уведомления Windows действительно появляются (проверена
  только регистрация), установка полного инсталлятора, машина без Npcap (страница установки
  Npcap), клики по фильтрам в окне WebView2 (логика проверена тестами в node и скриншотами
  headless Edge).

## Неочевидное в коде

- **Кодировки.** `installer/netscope.iss` и любой `.ps1` с не-ASCII символами — только UTF-8 **с
  BOM**: Inno Setup и Windows PowerShell 5.1 читают файл без BOM как ANSI (так и вышли битые 0.2.0 и
  0.3.0). `build-installer.ps1` отказывается собирать без BOM, `tests/installer.rs` это проверяет.
  Репозиторий хранит LF (`.gitattributes`).
- **Дашборд** — один файл `assets/index.html`. CSS не из Tailwind: `web::css` генерирует правила по
  именам классов на странице; неизвестный утилитарный класс роняет тест (`unknown_utilities`).
  Собственные компоненты (панель фильтров `.fbar`, `.fsel`, `.fchip`, `.fval`, `.fadd`, `.linkbtn`)
  описаны в `<style>`.
- **Блок `// BEGIN PURE … // END PURE`** в `index.html`: логика фильтров, группировка точек карты,
  раскладка подписей. Без DOM и глобальных переменных — `tests/ui_logic.rs` вырезает его и гоняет
  `tests/js/ui_logic.test.js` в node.
- **Smoke-тест рендера** (`tests/js/ui_render.test.js`) выполняет весь скрипт страницы в node на
  заглушках DOM и рендерит каждую вкладку на снимке демо-трафика (RU и EN). Новый глобальный API
  браузера в странице — добавить заглушку в `boot()`. Без node оба JS-теста пропускаются с
  сообщением `node not found`, а не падают: смотреть вывод.
- **Фильтры**: состояние каждой вкладки в `ui.facets[key]`, сохраняется в localStorage
  (`netscope.facets`) и в адресе (`f=` — JSON вида `{"country":["DE"]}`). DNS и журнал фильтруются
  на сервере: `/api/dns?f=&slow=&hide_local=`, `/api/journal?f=`; допустимые поля —
  `DNS_FACETS` (`views.rs`) и `journal::facet_fields`; общий механизм и счётчики — `analytics/facets.rs`.
  На вкладке Соединения кнопки дописывают язык запросов (поля `lan`, `idle` добавлены в 0.4.0).
- **Переводы**: словари RU и EN должны иметь одинаковые ключи (`tests/ui_i18n.rs`).
- **Ссылки `netscope://`**: действия, меняющие настройки (`mute`, `snooze`), принимаются только с
  ключом текущего процесса (`action_key` в `src/bin/app/main.rs`), иначе только открывается окно —
  защита от веб-страниц. e2e проверяет и это.

## Как выпустить релиз

1. Поднять версию в `Cargo.toml` (и пример в комментарии в начале `installer/netscope.iss`).
2. `cargo clippy --all-targets` и `cargo test --all-targets` (нужен node для JS-тестов).
3. Сборка (Inno Setup 6 — ищется в PATH, `%ISCC%` и `%LOCALAPPDATA%\Programs\InnoSetup6`;
   WebView2 и геобазы для полного инсталлятора кешируются в `installer\redist`):

   ```
   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1 -SkipBuild -Full
   ```

4. Портативный архив собирается вручную: `netscope.exe`, `netscope-app.exe`, `WebView2Loader.dll`,
   `LICENSE`, `LICENSE-WebView2Loader.txt` (из `assets/webview2/LICENSE.txt`), `README.md`,
   `scripts\fetch-geoip.ps1` → `dist\netscope-<версия>-windows-x64.zip`. Затем `SHA256SUMS.txt`
   (формат `<sha256>  <имя файла>`) по трём файлам.
5. E2e на живой машине (~2 минуты, нужен Npcap; NetScope ставится, запускается и удаляется,
   данные пользователя и ключи реестра на время отодвигаются и возвращаются):

   ```
   powershell -ExecutionPolicy Bypass -File scripts\e2e-installer.ps1 -Setup dist\NetScope-Setup-<версия>.exe
   ```

   Ожидается только PASS и в конце `restore: OK`; скриншоты и логи — в `%TEMP%\netscope-e2e`.
6. Коммит, аннотированный тег `v<версия>`, push в remote **`github`** (`origin` — GitLab, туда в
   этот период не пушили).
7. Релиз на GitHub через API (`gh` не установлен): описание в стиле прошлых релизов — на
   английском, таблица Downloads, разделы Fixed / New; четыре файла; `make_latest`.

Токен GitHub пользователь даёт на сессию. Передавать его только заголовком
(`git -c credential.helper= -c http.extraHeader="Authorization: Basic …" push github …`),
не записывать в `.git/config` и файлы.
