#!/bin/bash
# End-to-end test of the Dental Clinic API against a running server on :8000.
# Exits non-zero on the first failure. Run from backend/ after starting run.sh.
B=http://127.0.0.1:8000
pass=0; fail=0
ck() { # ck "label" expected_code actual_code
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS $1 ($3)"; else fail=$((fail+1)); echo "FAIL $1: want $2 got $3"; fi
}
j() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d$1)" 2>/dev/null; }

echo "== setup =="
S=$(curl -s -X POST $B/api/setup -H 'Content-Type: application/json' -d '{"name":"Dr. Test","username":"doctor","password":"doc1234"}')
echo "$S" | grep -q token && echo "PASS setup returns token" && pass=$((pass+1)) || { echo "FAIL setup: $S"; fail=$((fail+1)); }
TOK=$(echo "$S" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
S2=$(curl -s -o /dev/null -w "%{http_code}" -X POST $B/api/setup -H 'Content-Type: application/json' -d '{"name":"Second","username":"second","password":"xxxx"}')
ck "second setup rejected" 400 "$S2"
H="Authorization: Bearer $TOK"

echo "== staff user + login =="
C=$(curl -s -o /dev/null -w "%{http_code}" -X POST $B/api/users -H "$H" -H 'Content-Type: application/json' -d '{"name":"Reception One","username":"reception","password":"rec1234","role":"reception"}')
ck "create reception user" 200 "$C"
L=$(curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"mode":"staff","username":"reception","password":"rec1234"}')
echo "$L" | grep -q reception && echo "PASS reception login" && pass=$((pass+1)) || { echo "FAIL reception login: $L"; fail=$((fail+1)); }
L2=$(curl -s -o /dev/null -w "%{http_code}" -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"mode":"staff","username":"reception","password":"wrong"}')
ck "wrong password rejected" 401 "$L2"
ME=$(curl -s $B/api/auth/me -H "$H"); echo "$ME" | grep -q doctor && echo "PASS /auth/me" && pass=$((pass+1)) || { echo "FAIL me: $ME"; fail=$((fail+1)); }

echo "== patients (manual entry, empty start) =="
PL=$(curl -s $B/api/patients -H "$H"); [ "$PL" = "[]" ] && echo "PASS patients start EMPTY" && pass=$((pass+1)) || { echo "FAIL patients not empty: $PL"; fail=$((fail+1)); }
P=$(curl -s -X POST $B/api/patients -H "$H" -H 'Content-Type: application/json' -d '{"name":"Ahmed Test","age":30,"phone":"03001234567","allergy":"None","last_checkup":"2026-05-01","notes":"manual entry","pin":"1234"}')
PID=$(echo "$P" | j "['id']"); echo "patient id=$PID"
[ -n "$PID" ] && [ "$PID" != "None" ] && echo "PASS create patient" && pass=$((pass+1)) || { echo "FAIL create patient: $P"; fail=$((fail+1)); }
C=$(curl -s -o /dev/null -w "%{http_code}" -X POST $B/api/patients -H "$H" -H 'Content-Type: application/json' -d '{"name":"Dup","age":40,"phone":"03001234567"}')
ck "duplicate phone rejected" 400 "$C"
S2=$(curl -s "$B/api/patients?search=0300" -H "$H"); echo "$S2" | grep -q Ahmed && echo "PASS search by phone" && pass=$((pass+1)) || { echo "FAIL search: $S2"; fail=$((fail+1)); }

echo "== patient login =="
PL2=$(curl -s -X POST $B/api/auth/login -H 'Content-Type: application/json' -d '{"mode":"patient","phone":"03001234567","pin":"1234"}')
PTOK=$(echo "$PL2" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")
[ -n "$PTOK" ] && echo "PASS patient login phone+PIN" && pass=$((pass+1)) || { echo "FAIL patient login: $PL2"; fail=$((fail+1)); }
PH="Authorization: Bearer $PTOK"
C=$(curl -s -o /dev/null -w "%{http_code}" "$B/api/patients" -H "$PH")
ck "patient can list (own only)" 200 "$C"
C=$(curl -s -o /dev/null -w "%{http_code}" -X POST $B/api/patients -H "$PH" -H 'Content-Type: application/json' -d '{"name":"Nope","phone":"03009999999"}')
ck "patient cannot create patients" 403 "$C"

echo "== appointments =="
TODAY=$(date +%F)
A=$(curl -s -X POST $B/api/appointments -H "$H" -H 'Content-Type: application/json' -d "{\"patient_id\":$PID,\"date\":\"$TODAY\",\"time\":\"10:00 AM\",\"treatment_type\":\"RCT\"}")
AID=$(echo "$A" | j "['id']"); echo "appt id=$AID"
[ -n "$AID" ] && [ "$AID" != "None" ] && echo "PASS book appointment" && pass=$((pass+1)) || { echo "FAIL book: $A"; fail=$((fail+1)); }
C=$(curl -s -o /dev/null -w "%{http_code}" -X PUT $B/api/appointments/$AID -H "$H" -H 'Content-Type: application/json' -d '{"status":"Arrived"}')
ck "appointment status Arrived" 200 "$C"

echo "== treatments =="
T=$(curl -s -X POST $B/api/treatments -H "$H" -H 'Content-Type: application/json' -d "{\"patient_id\":$PID,\"type\":\"RCT\",\"tooth_no\":\"#36\",\"total_sittings\":3,\"total_fee\":6000,\"next_sitting\":\"$TODAY\"}")
TID=$(echo "$T" | j "['id']"); echo "treatment id=$TID"
[ -n "$TID" ] && [ "$TID" != "None" ] && echo "PASS create treatment" && pass=$((pass+1)) || { echo "FAIL treatment: $T"; fail=$((fail+1)); }
C=$(curl -s -X POST $B/api/treatments/$TID/complete-sitting -H "$H")
echo "$C" | grep -q '"done_sittings":1' && echo "PASS complete sitting 1/3" && pass=$((pass+1)) || { echo "FAIL sitting: $C"; fail=$((fail+1)); }

echo "== payments =="
PY=$(curl -s -X POST $B/api/payments -H "$H" -H 'Content-Type: application/json' -d "{\"treatment_id\":$TID,\"amount\":3000,\"mode\":\"JazzCash\",\"note\":\"Kisht 1\"}")
echo "$PY" | grep -q 3000 && echo "PASS payment entry" && pass=$((pass+1)) || { echo "FAIL payment: $PY"; fail=$((fail+1)); }
TV=$(curl -s "$B/api/treatments?patient_id=$PID" -H "$H")
echo "$TV" | grep -q '"remaining":3000' && echo "PASS remaining auto-calculated (6000-3000)" && pass=$((pass+1)) || { echo "FAIL remaining: $TV"; fail=$((fail+1)); }

echo "== xrays + teeth =="
X=$(curl -s -X POST $B/api/xrays -H "$H" -H 'Content-Type: application/json' -d "{\"patient_id\":$PID,\"tooth_no\":\"#36\",\"label\":\"X-ray #36\",\"note\":\"before RCT\"}")
echo "$X" | grep -q 'X-ray #36' && echo "PASS xray record" && pass=$((pass+1)) || { echo "FAIL xray: $X"; fail=$((fail+1)); }
C=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$B/api/patients/$PID/teeth/%2336" -H "$H" -H 'Content-Type: application/json' -d '{"status":"RCT"}')
ck "tooth status set" 200 "$C"
TG=$(curl -s "$B/api/patients/$PID/teeth" -H "$H"); echo "$TG" | grep -q RCT && echo "PASS teeth read" && pass=$((pass+1)) || { echo "FAIL teeth: $TG"; fail=$((fail+1)); }

echo "== patient self view =="
OV=$(curl -s $B/api/me/overview -H "$PH"); echo "$OV" | grep -q Ahmed && echo "$OV" | grep -q RCT && echo "PASS /me/overview" && pass=$((pass+1)) || { echo "FAIL overview: $OV"; fail=$((fail+1)); }

echo "== reports =="
for ep in dashboard "income?days=7" incomplete checkup-due pending-payments; do
  C=$(curl -s -o /dev/null -w "%{http_code}" "$B/api/reports/$ep" -H "$H"); ck "report $ep" 200 "$C"
done
D=$(curl -s $B/api/reports/dashboard -H "$H"); echo "$D" | grep -q '"today_income":3000' && echo "PASS dashboard today_income=3000" && pass=$((pass+1)) || { echo "FAIL dashboard: $D"; fail=$((fail+1)); }
DU=$(curl -s $B/api/reports/checkup-due -H "$H"); echo "$DU" | grep -q Ahmed && echo "PASS checkup-due lists patient (last checkup May)" && pass=$((pass+1)) || { echo "FAIL due: $DU"; fail=$((fail+1)); }
PP=$(curl -s $B/api/reports/pending-payments -H "$H"); echo "$PP" | grep -q '"remaining":3000' && echo "PASS pending-payments" && pass=$((pass+1)) || { echo "FAIL pending: $PP"; fail=$((fail+1)); }

echo "== web dashboard =="
C=$(curl -s -o /dev/null -w "%{http_code}" $B/); ck "web / serves" 200 "$C"
curl -s $B/ | grep -q "Doctor dashboard" && echo "PASS web index contains dashboard" && pass=$((pass+1)) || { echo "FAIL web content"; fail=$((fail+1)); }

echo "== auth guard =="
C=$(curl -s -o /dev/null -w "%{http_code}" $B/api/patients); ck "no token -> 401" 401 "$C"

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ]
