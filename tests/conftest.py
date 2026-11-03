"""Configuração comum dos testes."""

import os

# O TestClient do Starlette manda `Host: testserver`. A API só aceita localhost e o que estiver
# em VITRIX_ALLOWED_HOSTS (defesa contra DNS rebinding), então liberamos esse nome nos testes.
os.environ.setdefault("VITRIX_ALLOWED_HOSTS", "testserver")
