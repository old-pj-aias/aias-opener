check:
	cat parameters/fair_blind_signature.txt \
	| python -c 'import json; print(json.loads(input())["encrypted_id"])'