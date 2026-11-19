#!/usr/bin/env bash
# bw-audit.sh — Audit the passwords in an unencrypted Bitwarden JSON export.
#
# Finds reused, weak and breached passwords (Have I Been Pwned, k-anonymity).
# Passwords are never printed or saved.
#
# Usage:    ./bw-audit.sh [--lang en|it] [export.json]
#           Without --lang, the language is asked at startup (English by default).
# Requires: bash 4+, jq, curl, sha1sum (or shasum), base64
#           plus standard tools: awk, tr, sleep, date (shred if available)

set -euo pipefail

# ================================================================== Language
usage_err() { echo "Usage: $0 [--lang en|it] [export.json]" >&2; exit 2; }

L=""
FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lang|-l) L="${2:-}"; L="${L,,}"; shift; [[ $# -gt 0 ]] && shift
               [[ $L == en || $L == it ]] || usage_err ;;
    --lang=*)  L="${1#*=}"; L="${L,,}"; shift
               [[ $L == en || $L == it ]] || usage_err ;;
    -h|--help) echo "Usage: $0 [--lang en|it] [export.json]"; exit 0 ;;
    -*)        usage_err ;;
    *)         FILE="$1"; shift ;;
  esac
done

if [[ -z "$L" && -t 0 ]]; then
  echo "Language / Lingua:"
  echo "  1) English (default)"
  echo "  2) Italiano"
  read -rp "> " L || true
  echo
fi
case "${L,,}" in
  2|it|ita|italiano) L=it ;;
  *)                 L=en ;;
esac

declare -A T
if [[ $L == it ]]; then
  T=(
    [yes]="s"  [yn_y]="[S/n]"  [yn_n]="[s/N]"
    [error]="Errore:"
    [missing]="manca il comando '%s'"
    [no_json]="nessun file .json in questa cartella. Uso: %s export.json"
    [found]="File trovato: %s"
    [choose]="File JSON in questa cartella:"
    [not_found]="file non trovato: %s"
    [not_bw]="non sembra un export JSON di Bitwarden"
    [enc]="l'export è cifrato: esporta di nuovo scegliendo il formato .json (non cifrato)"
    [min_len]="Lunghezza minima per una password sicura [12]: "
    [summary]="RIEPILOGO – %s voci con password"
    [s_pwned]="Esposte nei breach:"
    [s_reused]="Riutilizzate:"
    [s_weak]="Deboli:"
    [s_ok]="OK:"
    [s_notchk]="non controllato"
    [s_note]="Ogni voce è contata una volta sola, nel problema più grave."
    [h_reused]="CAMBIA PRESTO – password riutilizzate"
    [d_reused]="Se uno di questi siti viene violato, gli altri sono a rischio. Una password diversa per ognuno."
    [h_weak]="MIGLIORA – password deboli"
    [d_weak]="Troppo corte o troppo semplici. Se l'account non ti serve più, puoi anche eliminarlo."
    [h_pwned]="CAMBIA SUBITO – password esposte"
    [d_pwned]="Queste password sono nelle liste usate dagli attaccanti. Cambiale ovunque compaiano."
    [none]="Nessun problema trovato."
    [no_pwned]="Nessuna password trovata nei breach."
    [hibp_info]="Il controllo online invia a haveibeenpwned.com solo i primi 5 caratteri\ndell'hash SHA-1 di ogni password, mai la password."
    [hibp_ask]="Controllare ora se le password sono state esposte in data breach?"
    [hibp_prog]="Controllo data breach %d/%d..."
    [hibp_err]="impossibile contattare haveibeenpwned.com"
    [j_pwned]="vista %s volte nei breach"
    [j_shared]="stessa password in %s voci"
    [j_weak]="debole: %s caratteri"
    [j_miss]="senza %s"
    [j_types]="minuscole,maiuscole,cifre,simboli"
    [j_and]=" e "
    [sep]="."
    [csv_ask]="Esportare il report in CSV (senza password)?"
    [csv_saved]="Salvato: %s"
    [csv_warn]="(contiene nomi utente e siti: non condividerlo)"
    [csv_head]="Priorità,Problema,Nome,Utente,URL,Vista nei breach,Voci con la stessa password,Lunghezza"
    [csv_types]=",Esposta,Riutilizzata,Debole"
    [del_info]="L'export contiene tutte le tue password in chiaro."
    [del_ask]="Cancellare ora %s?"
    [deleted]="Cancellato."
  )
else
  T=(
    [yes]="y"  [yn_y]="[Y/n]"  [yn_n]="[y/N]"
    [error]="Error:"
    [missing]="command '%s' not found"
    [no_json]="no .json file in this folder. Usage: %s export.json"
    [found]="File found: %s"
    [choose]="JSON files in this folder:"
    [not_found]="file not found: %s"
    [not_bw]="this does not look like a Bitwarden JSON export"
    [enc]="the export is encrypted: export again choosing the .json (unencrypted) format"
    [min_len]="Minimum length for a strong password [12]: "
    [summary]="SUMMARY – %s items with a password"
    [s_pwned]="Breached:"
    [s_reused]="Reused:"
    [s_weak]="Weak:"
    [s_ok]="OK:"
    [s_notchk]="not checked"
    [s_note]="Each item is counted once, under its most serious problem."
    [h_reused]="CHANGE SOON – reused passwords"
    [d_reused]="If one of these sites is breached, the others are at risk. Use a different password for each."
    [h_weak]="IMPROVE – weak passwords"
    [d_weak]="Too short or too simple. If you no longer need the account, you can delete it."
    [h_pwned]="CHANGE NOW – breached passwords"
    [d_pwned]="These passwords are on the lists attackers use. Change them everywhere they appear."
    [none]="No problems found."
    [no_pwned]="No passwords found in breaches."
    [hibp_info]="The online check sends haveibeenpwned.com only the first 5 characters\nof each password's SHA-1 hash, never the password itself."
    [hibp_ask]="Check now whether your passwords appear in data breaches?"
    [hibp_prog]="Checking breaches %d/%d..."
    [hibp_err]="cannot reach haveibeenpwned.com"
    [j_pwned]="seen %s times in breaches"
    [j_shared]="same password in %s items"
    [j_weak]="weak: %s characters"
    [j_miss]="no %s"
    [j_types]="lowercase,uppercase,digits,symbols"
    [j_and]=" or "
    [sep]=","
    [csv_ask]="Export the report as CSV (no passwords)?"
    [csv_saved]="Saved: %s"
    [csv_warn]="(contains usernames and sites: do not share it)"
    [csv_head]="Priority,Problem,Name,Username,URL,Seen in breaches,Items with the same password,Length"
    [csv_types]=",Breached,Reused,Weak"
    [del_info]="The export contains all your passwords in plain text."
    [del_ask]="Delete %s now?"
    [deleted]="Deleted."
  )
fi

# t KEY [args...] → translated string, printf-style
# The format strings are the translation tables above, never user data.
# shellcheck disable=SC2059
t() { local k="$1"; shift; printf -- "${T[$k]}" "$@"; }

# ================================================================== Helpers
if [[ -t 1 ]]; then
  R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[34m'; G=$'\e[32m'; D=$'\e[2m'; BO=$'\e[1m'; N=$'\e[0m'
else
  R=""; Y=""; B=""; G=""; D=""; BO=""; N=""
fi

die() { echo "${R}$(t error)${N} $*" >&2; exit 1; }

# ask "Question" default(y/n) → returns 0 on yes
ask() {
  local q="$1" def="$2" ans
  [[ ! -t 0 ]] && return 1   # no terminal: never do anything implicitly
  read -rp "$q $([[ $def == y ]] && t yn_y || t yn_n) " ans || { echo; return 1; }  # EOF = no
  [[ -z $ans ]] && { [[ $def == y ]]; return; }
  [[ ${ans,,} == "$(t yes)"* || ${ans,,} == y* ]]
}

# ================================================================== Requirements
for cmd in jq base64; do
  command -v "$cmd" >/dev/null || die "$(t missing "$cmd")"
done
if command -v sha1sum >/dev/null; then SHA1=(sha1sum)
elif command -v shasum >/dev/null; then SHA1=(shasum -a 1)
else die "$(t missing sha1sum)"; fi
# base64 decode: -d on GNU, BusyBox/Toybox and recent macOS, -D on older macOS
if   [[ $(printf 'aGk=' | base64 -d 2>/dev/null) == hi ]]; then B64D=(base64 -d)
elif [[ $(printf 'aGk=' | base64 -D 2>/dev/null) == hi ]]; then B64D=(base64 -D)
else die "$(t missing "base64 -d")"; fi

# ================================================================== Input file
if [[ -z "$FILE" ]]; then
  shopt -s nullglob
  JSONS=(./*.json)
  JSONS=("${JSONS[@]#./}")
  shopt -u nullglob
  case ${#JSONS[@]} in
    0) die "$(t no_json "$0")" ;;
    1) FILE="${JSONS[0]}"; t found "${BO}$FILE${N}"; echo ;;
    *) t choose; echo
       select f in "${JSONS[@]}"; do [[ -n "$f" ]] && { FILE="$f"; break; }; done ;;
  esac
fi
[[ -f "$FILE" ]] || die "$(t not_found "$FILE")"
[[ $FILE == -* ]] && FILE="./$FILE"   # names starting with "-" are not options
# Encrypted exports: "encrypted": true, and "2.<iv>|<data>|<mac>" cipher strings
jq -e '.encrypted == true
       or any(.items[]?; (.login.password // "")
              | test("^2\\.[A-Za-z0-9+/]{22}==\\|[A-Za-z0-9+/=]+\\|[A-Za-z0-9+/]{43}=$"))' \
  "$FILE" >/dev/null 2>&1 && die "$(t enc)"
jq -e '(.items | type == "array")
       and all(.items[]; (.type | type == "number") and (.name | type == "string"))' "$FILE" >/dev/null 2>&1 \
  || die "$(t not_bw)"

MIN_LEN=12
if [[ -t 0 ]]; then
  read -rp "$(t min_len)" ans || true
  [[ ${ans:-} =~ ^[0-9]+$ ]] && MIN_LEN="$ans"
fi
echo

# ================================================================== Offline analysis
# One element per distinct password: {k: base64 password, len, cls, items}
GROUPS_JSON=$(jq -c '
  [.items[]
   | select(.type == 1 and (.login.password // "") != "")
   | {n: .name, u: (.login.username // ""), url: (.login.uris[0].uri // ""),
      p: .login.password}]
  | group_by(.p)
  | map(.[0].p as $p | {
      k: ($p | @base64),
      len: ($p | length),
      has: [($p | test("\\p{Ll}")), ($p | test("\\p{Lu}")),
            ($p | test("\\p{Nd}")), ($p | test("[^\\p{L}\\p{Nd}]"))],
      items: map({n, u, url})
    } | .cls = (.has | map(select(.)) | length)
      | .miss = [.has | to_entries[] | select(.value | not) | .key]
      | del(.has))
' "$FILE")

NGROUPS=$(jq 'length' <<<"$GROUPS_JSON")
NITEMS=$(jq '[.[].items | length] | add // 0' <<<"$GROUPS_JSON")

# build_report EXPOSED_JSON → groups with problems and priority, without secrets
# priority: 1 = breached, 2 = reused, 3 = weak, 4 = ok
build_report() {
  jq -c --argjson exp "$1" --argjson min "$MIN_LEN" '
    to_entries | map(.value + {
      pwned: ($exp[.key | tostring] // 0),
      shared: (.value.items | length),
      weak: (.value.len < $min or (.value.cls < 3 and .value.len < 20))
    } | del(.k)
    | . + {prio: (if .pwned > 0 then 1 elif .shared > 1 then 2
                  elif .weak then 3 else 4 end)})
  ' <<<"$GROUPS_JSON"
}

# section COLOR TITLE DESCRIPTION JQ_FILTER
# jq program: the $ variables belong to jq, not to the shell
# shellcheck disable=SC2016
SECTION_JQ='
  def fmt($s; $a): reduce $a[] as $x ($s; sub("%s"; "\($x)"));
  def th: tostring | if length > 3 then (.[:-3] | th) + $sep + .[-3:] else . end;
  def list: if length < 2 then join("")
            else (.[:-1] | join(", ")) + $and + .[-1] end;
  def who: $n + .n + (if .u != "" then " " + $d + "(" + .u + ")" + $n else "" end);
  def why:
    [ (if .pwned > 0 then fmt($jp; [.pwned | th]) else empty end),
      (if .shared > 1 then fmt($js; [.shared]) else empty end),
      (if .weak then fmt($jw; [.len])
         + (if (.miss | length) > 0
            then ", " + fmt($jm; [[.miss[] | ($types | split(","))[.]] | list])
            else "" end)
       else empty end)
    ] | join(" · ");
  map(select(FILTER)) | sort_by(-.pwned, -.shared, .len) | .[]
  | "  " + $c + "● " + why + $n + "\n"
    + (.items | map("  " + $c + "│" + $n + "   " + who) | join("\n"))
'
section() {
  local out
  out=$(jq -r --arg jp "${T[j_pwned]}" --arg js "${T[j_shared]}" \
              --arg jw "${T[j_weak]}" --arg jm "${T[j_miss]}" \
              --arg types "${T[j_types]}" --arg and "${T[j_and]}" \
              --arg sep "${T[sep]}" --arg c "$1" --arg d "$D" --arg n "$N" \
              "${SECTION_JQ//FILTER/$4}" <<<"$REPORT")
  [[ -z "$out" ]] && return 1
  local bar
  bar=""; for _ in {1..60}; do bar+="━"; done
  echo "${1}${bar}${N}"
  echo "${1}${BO} $2${N}"
  echo "${D} $3${N}"
  echo "${1}${bar}${N}"
  echo "$out"
  echo
}

count_items() { jq --argjson p "$1" '[.[] | select(.prio == $p) | .shared] | add // 0' <<<"$REPORT"; }

summary() {
  local c1 c2 c3 c4 lw nw l
  c1=$(count_items 1); c2=$(count_items 2); c3=$(count_items 3); c4=$(count_items 4)
  # label width = longest label, number width = digits of the total
  lw=0
  for l in s_pwned s_reused s_weak s_ok; do
    (( ${#T[$l]} > lw )) && lw=${#T[$l]}
  done
  nw=${#NITEMS}
  echo "${BO}$(t summary "$NITEMS")${N}"
  if [[ $HIBP -eq 1 ]]; then printf "  ${R}%-${lw}s  %${nw}s${N}\n" "$(t s_pwned)" "$c1"
  else printf "  ${D}%-${lw}s  %s${N}\n" "$(t s_pwned)" "$(t s_notchk)"; fi
  printf "  ${Y}%-${lw}s  %${nw}s${N}\n" "$(t s_reused)" "$c2"
  printf "  ${B}%-${lw}s  %${nw}s${N}\n" "$(t s_weak)" "$c3"
  printf "  ${G}%-${lw}s  %${nw}s${N}\n" "$(t s_ok)" "$c4"
  echo "${D}$(t s_note)${N}"
  echo
  PROBLEMS=$((c1 + c2 + c3))
}

HIBP=0
REPORT=$(build_report '{}')
section "$Y" "$(t h_reused)" "$(t d_reused)" '.shared > 1' || true
section "$B" "$(t h_weak)"   "$(t d_weak)"   '.shared == 1 and .weak' || true

# ================================================================== Online check (last)
echo -e "${D}$(t hibp_info)${N}"
if ask "$(t hibp_ask)" y; then
  command -v curl >/dev/null || die "$(t missing curl)"
  HIBP=1
  EXPOSED="{}"
  i=0
  while IFS= read -r b64; do
    [[ -t 1 ]] && printf '\r%s%s%s' "$D" "$(t hibp_prog "$((i + 1))" "$NGROUPS")" "$N"
    hash=$(printf '%s' "$b64" | "${B64D[@]}" | "${SHA1[@]}" | awk '{print toupper($1)}')
    resp=$(curl -sf --connect-timeout 10 --max-time 30 -H "Add-Padding: true" -A "bw-audit.sh" \
           "https://api.pwnedpasswords.com/range/${hash:0:5}") \
      || { echo; die "$(t hibp_err)"; }
    count=$(tr -d '\r' <<<"$resp" | awk -F: -v s="${hash:5}" '$1 == s {print $2}')
    [[ -n "$count" && "$count" != "0" ]] \
      && EXPOSED=$(jq -c --arg i "$i" --argjson c "$count" '. + {($i): $c}' <<<"$EXPOSED")
    i=$((i + 1))
    sleep 0.1
  done < <(jq -r '.[].k' <<<"$GROUPS_JSON")
  [[ -t 1 ]] && printf '\r\e[K'
  echo

  REPORT=$(build_report "$EXPOSED")
  section "$R" "$(t h_pwned)" "$(t d_pwned)" '.pwned > 0' \
    || { echo "${G}$(t no_pwned)${N}"; echo; }
else
  echo
fi
unset GROUPS_JSON

# ================================================================== Summary
summary
[[ $PROBLEMS -eq 0 ]] && { echo "${G}$(t none)${N}"; echo; }

# ================================================================== CSV export
if [[ $PROBLEMS -gt 0 ]] && ask "$(t csv_ask)" n; then
  OUT="bw-audit-$(date +%Y%m%d-%H%M).csv"
  ( umask 077
    jq -r --arg head "${T[csv_head]}" --arg types "${T[csv_types]}" '
      # neutralize spreadsheet formulas (CSV injection)
      def safe: if test("^[\\s\\p{Cc}]*[=+\\-@]") then "\u0027" + . else . end;
      ($types | split(",")) as $ty
      | ($head | split(",")),
        ( sort_by(.prio, -.pwned, -.shared) | .[] | select(.prio < 4) as $g
          | $g.items[]
          | [$g.prio, $ty[$g.prio], (.n | safe), (.u | safe), (.url | safe), $g.pwned, $g.shared, $g.len] )
      | @csv
    ' <<<"$REPORT" > "$OUT" )
  echo "$(t csv_saved "${BO}$OUT${N}") ${D}$(t csv_warn)${N}"
fi

# ================================================================== Cleanup
echo
echo "${D}$(t del_info)${N}"
if ask "$(t del_ask "$FILE")" n; then
  if command -v shred >/dev/null; then shred -u "$FILE"; else rm -f "$FILE"; fi
  t deleted; echo
fi
