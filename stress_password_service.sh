#!/usr/bin/env bash
set -euo pipefail

# ==============================
# Настройки
# ==============================

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
BASE_URL="http://${HOST}:${PORT}"

# сколько всего запросов и параллельность

TOTAL_REQUESTS=${TOTAL_REQUESTS:-20000}
CONCURRENCY=${CONCURRENCY:-64}
EXISTING_COUNT=${EXISTING_COUNT:-50}

# сколько тестовых записей создать заранее
EXISTING_COUNT=${EXISTING_COUNT:-20}

echo "Target:  ${BASE_URL}"
echo "Total:   ${TOTAL_REQUESTS} requests"
echo "Workers: ${CONCURRENCY}"
echo "Records: ${EXISTING_COUNT} precreated entries"
echo

# ==============================
# health-check
# ==============================

echo "[*] Health check..."
if ! curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health" | grep -q "200"; then
    echo "[-] /health не 200, сервис мёртвый или недоступен"
    exit 1
fi
echo "[+] OK, живой."
echo

# ==============================
# Подготовка тестовых записей
# ==============================

echo "[*] Создаю ${EXISTING_COUNT} тестовых записей через /add..."

for i in $(seq 1 "${EXISTING_COUNT}"); do
    # простой безопасный пароль (hex, чтобы не париться с JSON)
    pw=$(openssl rand -hex 16 2>/dev/null || echo "pw_${RANDOM}_${i}")
    name="test_${i}"
    user="user_${i}"

    curl -s -o /dev/null -X POST "${BASE_URL}/add" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"${name}\",\"username\":\"${user}\",\"password\":\"${pw}\"}"
done

echo "[+] Тестовые записи созданы."
echo

# ==============================
# Функции для разных сценариев
# ==============================

do_health_ok() {
  curl -s -o /dev/null "${BASE_URL}/health"
}

do_generate_ok() {
  local len=$(( 8 + RANDOM % 40 ))
  local symbols=$(( RANDOM % 2 ))
  local symbols_flag="false"
  [[ "$symbols" -eq 1 ]] && symbols_flag="true"

  curl -s -o /dev/null -X POST "${BASE_URL}/generate" \
    -H "Content-Type: application/json" \
    -d "{
      \"length\":  ${len},
      \"upper\":   true,
      \"lower\":   true,
      \"digits\":  true,
      \"symbols\": ${symbols_flag}
    }"
}

do_generate_bad() {
  # специально мусор вместо JSON → 400
  curl -s -o /dev/null -X POST "${BASE_URL}/generate" \
    -H "Content-Type: application/json" \
    -d 'not a json at all'
}

do_add_ok() {
  local id=$(( 100000 + RANDOM % 900000 ))
  local pw=$(openssl rand -hex 16 2>/dev/null || echo "pw_${RANDOM}_${id}")
  local name="load_${id}"
  local user="user_${id}"

  curl -s -o /dev/null -X POST "${BASE_URL}/add" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${name}\",\"username\":\"${user}\",\"password\":\"${pw}\"}"
}

do_add_bad() {
  # нет поля name → 400
  curl -s -o /dev/null -X POST "${BASE_URL}/add" \
    -H "Content-Type: application/json" \
    -d '{"username":"no_name","password":"pw"}'
}

do_get_ok() {
  # берём одну из заранее созданных записей: test_1..test_N
  local idx=$(( 1 + RANDOM % EXISTING_COUNT ))
  local name="test_${idx}"

  curl -s -o /dev/null -X POST "${BASE_URL}/get" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${name}\"}"
}

do_get_not_found() {
  local name="no_such_record_${RANDOM}"

  curl -s -o /dev/null -X POST "${BASE_URL}/get" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${name}\"}"
}

# ==============================
# Один запрос: выбираем сценарий
# ==============================

single_request() {
  # RANDOM в bash глобальный, пофиг на аргументы
  local r=$(( RANDOM % 10 ))

  case "$r" in
    0)
      # немного health
      do_health_ok
      ;;
    1|2)
      # большинство – валидный generate
      do_generate_ok
      ;;
    3)
      # generate с ошибкой (400)
      do_generate_bad
      ;;
    4|5)
      # get существующий (200)
      do_get_ok
      ;;
    6)
      # get несуществующий (404)
      do_get_not_found
      ;;
    7|8)
      # add валидный (200)
      do_add_ok
      ;;
    9)
      # add с ошибкой (400)
      do_add_bad
      ;;
  esac
}

export BASE_URL EXISTING_COUNT
export -f do_health_ok do_generate_ok do_generate_bad
export -f do_add_ok do_add_bad do_get_ok do_get_not_found
export -f single_request

# ==============================
# Запуск нагрузки
# ==============================

echo "[*] Старт нагрузки..."
start_ts=$(date +%s)

seq 1 "${TOTAL_REQUESTS}" | xargs -n1 -P"${CONCURRENCY}" bash -c 'single_request' _

end_ts=$(date +%s)
elapsed=$(( end_ts - start_ts ))
[[ "$elapsed" -eq 0 ]] && elapsed=1

echo
echo "[+] Готово."
echo "    Время: ${elapsed} сек"
echo "    Примерный RPS: $(( TOTAL_REQUESTS / elapsed ))"
