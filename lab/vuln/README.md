# lab/vuln — 취약 훈련표적 "탐지" (스캔 전용, 침투 X)

공개된 취약 훈련 이미지(OWASP Juice Shop)를 띄우고 Ballista의 **nuclei 취약점 탐지**를
돌린다. Ballista가 하는 것은 "여기 취약점이 존재한다"를 **탐지·기록·탐지공백 리포트**까지다
— 뚫는 게 아니라 존재를 스캔하는 nuclei 어댑터 본연의 방어 기능.

```bash
docker run -d --name ballista-vuln -p 127.0.0.1:13000:3000 bkimminich/juice-shop
python sign_scope.py lab/vuln/scope.yaml lab/vuln/keys
python -m ballista.cli run lab/vuln/scope.yaml lab/vuln/keys lab/vuln/actions.json \
    --db lab/vuln/evidence.db      # nuclei 탐지(태그 tech/exposure/misconfig/headers)
python -m ballista.cli report-doc lab/vuln/scope.yaml lab/vuln/keys \
    --db lab/vuln/evidence.db --out lab/vuln/report.md
docker rm -f ballista-vuln
```
