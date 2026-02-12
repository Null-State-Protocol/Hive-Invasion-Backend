#!/bin/bash

# Test New Gameplay Endpoints
BASE_URL="https://9ftunrhyo4.execute-api.eu-north-1.amazonaws.com/prod"

echo "=== Creating Test User ==="
SIGNUP_RESPONSE=$(curl -s -X POST "$BASE_URL/game/signup" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"test_gameplay_$(date +%s)@example.com\", \"password\": \"TestPass123!\", \"username\": \"TestPlayer$(date +%s)\"}")

echo "$SIGNUP_RESPONSE" | python3 -m json.tool
ACCESS_TOKEN=$(echo "$SIGNUP_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', ''))")

if [ -z "$ACCESS_TOKEN" ]; then
  echo "❌ Failed to get access token"
  exit 1
fi

echo -e "\n✅ Got access token\n"

# Test 1: Get Player Profile (should include new fields)
echo "=== Test 1: Get Player Profile ==="
curl -s -X GET "$BASE_URL/game/player/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | python3 -m json.tool

# Test 2: Get Pilots
echo -e "\n=== Test 2: Get Pilots ==="
curl -s -X GET "$BASE_URL/game/player/pilots" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | python3 -m json.tool

# Test 3: Unlock a Pilot
echo -e "\n=== Test 3: Unlock Pilot ==="
curl -s -X POST "$BASE_URL/game/player/pilots/unlock" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pilot_id": "pilot_ace"}' | python3 -m json.tool

# Test 4: Get Mechs
echo -e "\n=== Test 4: Get Mechs ==="
curl -s -X GET "$BASE_URL/game/player/mechs" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | python3 -m json.tool

# Test 5: Unlock a Mech
echo -e "\n=== Test 5: Unlock Mech ==="
curl -s -X POST "$BASE_URL/game/player/mechs/unlock" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mech_id": "mech_tank", "variant": "blue"}' | python3 -m json.tool

# Test 6: Get Active Boosts
echo -e "\n=== Test 6: Get Active Boosts ==="
curl -s -X GET "$BASE_URL/game/player/boosts" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | python3 -m json.tool

# Test 7: Activate a Boost
echo -e "\n=== Test 7: Activate Boost ==="
curl -s -X POST "$BASE_URL/game/player/boosts/activate" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"boost_id": "boost_001", "boost_name": "XP_2X", "duration_seconds": 3600}' | python3 -m json.tool

# Test 8: Get Skills
echo -e "\n=== Test 8: Get Skills ==="
curl -s -X GET "$BASE_URL/game/player/skills" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | python3 -m json.tool

# Test 9: Unlock a Skill
echo -e "\n=== Test 9: Unlock Skill ==="
curl -s -X POST "$BASE_URL/game/player/skills/unlock" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"skill_id": "skill_rapid_fire", "slot": 1}' | python3 -m json.tool

# Test 10: Update Gems
echo -e "\n=== Test 10: Update Gems ==="
curl -s -X POST "$BASE_URL/game/player/gems/update" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 500}' | python3 -m json.tool

# Test 11: Update Dust
echo -e "\n=== Test 11: Update Dust ==="
curl -s -X POST "$BASE_URL/game/player/dust/update" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 100}' | python3 -m json.tool

# Test 12: Start Session
echo -e "\n=== Test 12: Start Session ==="
SESSION_RESPONSE=$(curl -s -X POST "$BASE_URL/game/session/start" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
echo "$SESSION_RESPONSE" | python3 -m json.tool

SESSION_ID=$(echo "$SESSION_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('session_id', ''))")

if [ ! -z "$SESSION_ID" ]; then
  echo -e "\n=== Test 13: End Session (with dust reward) ==="
  curl -s -X POST "$BASE_URL/game/session/end" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\": \"$SESSION_ID\", \"score\": 1000, \"kills\": 50, \"waves_survived\": 10, \"performance_metrics\": {\"accuracy\": 85}}" | python3 -m json.tool
fi

echo -e "\n✅ All tests complete!"
