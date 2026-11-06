# Logen KHPay (core backend)
Multi-user KHQR API: users add their own provider key (ABA / Bakong via https://khqrpay.site), create `sk_live_` keys, call `/api/v1/*`.

## Run locally
    pip install -r requirements.txt
    cp .env.example .env   # fill FERNET_KEY, SECRET_KEY
    export $(grep -v '^#' .env | xargs); uvicorn main:app --reload

## Deploy to Render
Push to GitHub -> Render Blueprint (render.yaml). Set FERNET_KEY, ADMIN_EMAIL, PUBLIC_BASE_URL, PROVIDER_CHECK_URL.

## SETUP REQUIREMENT (provider)
Create endpoints follow the documented contract. The provider's payment-status endpoint and response field names were not provided,
so set `PROVIDER_CHECK_URL` (placeholder `{ref}`) from the khqrpay.site docs and verify field names in `create()` / `refresh()`.
No auto-provisioning is assumed: each user pastes their own provider key (Fernet-encrypted, never returned).

## Test
    curl -X POST $URL/auth/register -H 'Content-Type: application/json' -d '{"email":"a@b.com","password":"password123"}' -c jar
    curl -X POST $URL/dashboard/merchants -b jar -H 'Content-Type: application/json' -d '{"kind":"aba","name":"Shop","provider_key":"PROVIDER_KEY"}'
    curl -X POST $URL/dashboard/keys -b jar -H 'Content-Type: application/json' -d '{"name":"main"}'
    curl -X POST $URL/api/v1/aba/create -H 'Authorization: Bearer sk_live_...' -H 'Content-Type: application/json' -d '{"amount":5}'
