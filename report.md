# Звіт архітектурного аудиту: Secure by Design

## Мета аудиту

Виявити архітектурні порушення контрольованості та перевіряльності системи, визначити відсутні сигнали та запропонувати виправлення на основі патернів з конспекту.

---

## Чеклист архітектурних сигналів

| Сигнал                        | Є / Немає | Коментар                                             |
| ----------------------------- | --------- | ---------------------------------------------------- |
| OpenAPI / `response_model`    | Немає     | FastAPI без response_model, API не документовано     |
| Типізація даних (Pydantic)    | Немає     | Вхідні параметри без типів, request.json() без схеми |
| Secrets через Vault / CSI     | Немає     | Використовується secretRef без CSI driver            |
| CI перевірки (Trivy, Semgrep) | Немає     | Лише docker build, жодних security gates             |
| Логування дій                 | Немає     | Відсутнє структуроване логування                     |
| OPA / policy-as-code          | Немає     | Авторизація захардкоджена в коді                     |
| Ізоляція середовища           | Немає     | Security group відкрита на 0.0.0.0/0                 |
| Мінімальні привілеї (PoLP)    | Немає     | Порушено в main.tf та deployment.yaml                |
| SBOM / підпис контейнера      | Немає     | Dockerfile без syft/cosign                           |

---

## Виявлені проблеми

---

### Проблема 1: Відсутність типізації та OpenAPI-контракту

**Файл:** `main.py`

```python
@app.get("/user")
def get_user(id):
    # no typing, no response_model, no validation
    return {"id": id, "name": "Alice"}

@app.post("/login")
def login(request: Request):
    data = request.json()  # no schema, unsafe parsing
```

**Пояснення:**
Система не продукує структурованих сигналів для перевірки. Без типізації (Pydantic) та `response_model` інструменти SAST (Semgrep) не можуть ідентифікувати user input, а DAST-сканери не знають структуру API для fuzzing. Параметр `id` не має типу — це порушує принцип "наявності сигналів" з конспекту: _"Архітектура повинна продукувати структуровані об'єкти, які можна перевірити: OpenAPI-контракти, типізовані моделі"_.

**Розділ/патерн конспекту:**

- Патерн "Типізація даних (DTO, Pydantic)" — дає можливість статичного аналізу та валідації
- Патерн "OpenAPI 3.0 контракт" — робить сервіс видимим для DAST-сканерів
- Принцип "Наявність сигналів" — без сигналу немає перевірки

**Виправлення:**

```python
from pydantic import BaseModel
from uuid import UUID

class UserResponse(BaseModel):
    id: UUID
    name: str

class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/user", response_model=UserResponse)
def get_user(id: UUID) -> UserResponse:
    return UserResponse(id=id, name="Alice")

@app.post("/login")
def login(data: LoginRequest):
    # Валідація автоматична через Pydantic
    ...
```

---

### Проблема 2: Секрети без Vault CSI — відсутність централізованого контролю

**Файл:** `deployment.yaml`

```yaml
spec:
  containers:
    - name: user-api
      envFrom:
        - secretRef:
            name: user-api-secrets
```

**Пояснення:**
Секрети передаються через Kubernetes secretRef, але без інтеграції з Vault CSI driver. Це означає:

- Секрети зберігаються в etcd кластера без шифрування at-rest (за замовчуванням)
- Відсутній централізований аудит доступу до секретів
- Неможливо автоматично ротувати секрети
- Gitleaks не бачить секрет, якщо він створений вручну через `kubectl create secret`

Як зазначено в конспекті: _"secrets scanner не бачить секрет, який підвантажується з secret.txt, не збереженого в git"_.

**Розділ/патерн конспекту:**

- Патерн "Vault CSI для зберігання секретів" — забезпечує централізований аудит
- Принцип "Локалізація точок перевірки" — гейти мають знати, де шукати порушення

**Виправлення:**

```yaml
spec:
  serviceAccountName: user-api
  volumes:
    - name: secrets-store
      csi:
        driver: secrets-store.csi.k8s.io
        readOnly: true
        volumeAttributes:
          secretProviderClass: vault-user-api
  containers:
    - name: user-api
      volumeMounts:
        - name: secrets-store
          mountPath: '/mnt/secrets-store'
          readOnly: true
---
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: vault-user-api
spec:
  provider: vault
  parameters:
    vaultAddress: 'https://vault.internal:8200'
    roleName: 'user-api'
    objects: |
      - objectName: "api-key"
        secretPath: "secret/data/user-api"
        secretKey: "API_KEY"
```

---

### Проблема 3: CI/CD без security gates — система "мовчить"

**Файл:** `ci.yml`

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Build container
        run: docker build -t user-api .
```

**Пояснення:**
Пайплайн виконує лише checkout та build — жодних перевірок безпеки. Це критичне порушення принципу Secure by Design: _"Система не повинна залежати від «уважності» розробника або від того, чи згадає команда запустити аналіз"_.

Відсутні:

- **Gitleaks** — секрети можуть потрапити в git
- **Semgrep/SAST** — вразливості коду не виявляються
- **Trivy** — CVE в залежностях не блокуються
- **SBOM (syft)** — неможливо відстежити supply chain
- **tfsec** — IaC не перевіряється

Як зазначено в конспекті: _"Trivy не аналізує залежності, якщо не створено SBOM"_.

**Розділ/патерн конспекту:**

- Принцип "CI/CD-гейти — гаранти незмінності"
- Патерн "SBOM і підпис артефактів (supply chain)"
- Принцип "Інтерпретація результатів" — пайплайн має визначення, що робити при порушенні

**Виправлення:**

```yaml
name: CI
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Gitleaks - secrets scanning
        uses: gitleaks/gitleaks-action@v2

      - name: Semgrep - SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: p/python

      - name: Build container
        run: docker build -t user-api .

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: user-api
          format: spdx-json
          output-file: sbom.json

      - name: Trivy - CVE scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: user-api
          exit-code: '1'
          severity: 'CRITICAL,HIGH'

      - name: tfsec - IaC scan
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: .

      - name: Sign container
        run: cosign sign --key cosign.key user-api
```

---

### Проблема 4: Відкрита Security Group — порушення PoLP

**Файл:** `main.tf`

```hcl
resource "aws_security_group" "user_api" {
  name        = "user-api-sg"
  description = "Allow 443 from anywhere"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # відкрита зона
  }
}
```

**Пояснення:**
CIDR block `0.0.0.0/0` дозволяє трафік з будь-якої IP-адреси в інтернеті. Це пряме порушення принципу найменших привілеїв (PoLP — Principle of Least Privilege).

Навіть якщо tfsec встановлено, без явної політики OPA/conftest ця конфігурація може пройти в production. Як зазначено в конспекті: _"tfsec не спрацьовує, якщо інфраструктура описана вручну в cloud console"_ — але тут проблема інша: IaC є, але немає гейту, який би заблокував небезпечну конфігурацію.

**Розділ/патерн конспекту:**

- Патерн "IaC як єдине довірене джерело конфігурацій"
- Патерн "Policy-as-Code за допомогою OPA" — контроль через deny rules
- Принцип мінімальних привілеїв (PoLP)

**Виправлення:**

**main.tf:**

```hcl
variable "allowed_cidr_blocks" {
  description = "List of allowed CIDR blocks"
  type        = list(string)
  default     = ["10.0.0.0/8"]  # Тільки внутрішня мережа
}

resource "aws_security_group" "user_api" {
  name        = "user-api-sg"
  description = "Allow 443 from trusted networks only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

**OPA policy (policy/security_group.rego):**

```rego
package terraform

deny[msg] {
  resource := input.resource.aws_security_group[name]
  cidr := resource.ingress[_].cidr_blocks[_]
  cidr == "0.0.0.0/0"
  msg := sprintf("Security group '%s' allows traffic from 0.0.0.0/0 - violates PoLP", [name])
}
```

---

### Проблема 5: Dockerfile без SBOM та підпису — supply chain не контролюється

**Файл:** `Dockerfile`

```dockerfile
FROM python:3.10

WORKDIR /app
COPY app /app
RUN pip install fastapi uvicorn

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Пояснення:**
Контейнер не має:

- **SBOM** — неможливо перевірити залежності на CVE
- **Цифрового підпису** — неможливо гарантувати, що імідж пройшов перевірку
- **requirements.txt** — залежності не зафіксовані, `pip install` без lock-файлу
- **Мінімального base image** — python:3.10 містить багато непотрібних пакетів

Як зазначено в конспекті: _"pip install x у Bash — не створює відтворювану структуру"_ та _"Trivy не аналізує залежності, якщо не створено SBOM"_.

**Розділ/патерн конспекту:**

- Патерн "SBOM і підпис артефактів (supply chain)"
- Сигнали компонентів: "Lock-файли (package-lock.json, go.sum)"
- Принцип "Контроль походження (provenance)"

**Виправлення:**

**requirements.txt:**

```
fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.2
```

**Dockerfile:**

```dockerfile
FROM python:3.10-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.10-slim

# Security: non-root user
RUN useradd -m -u 1000 appuser
USER appuser

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --chown=appuser:appuser app /app

# Generate SBOM at build time
LABEL org.opencontainers.image.source="https://github.com/org/user-api"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**CI step для SBOM та підпису:**

```yaml
- name: Generate SBOM
  run: syft user-api -o spdx-json > sbom.json

- name: Sign image
  run: cosign sign --key cosign.key user-api:latest

- name: Attach SBOM to image
  run: cosign attach sbom --sbom sbom.json user-api:latest
```

---

### Проблема 6: Відсутність структурованого логування

**Файл:** `main.py`

```python
@app.post("/login")
def login(request: Request):
    data = request.json()
    if data["password"] == "secret":
        return {"status": "ok"}
    return {"status": "fail"}
```

**Пояснення:**
Відсутнє будь-яке логування дій. Це означає:

- SIEM не отримує події для аналізу
- Неможливо виявити brute-force атаки на `/login`
- Відсутній audit trail для compliance
- Інциденти неможливо розслідувати

Як зазначено в конспекті: _"print() у коді — не має структури, не агрегується"_ та _"Логи відображаються через print() — неможливо зібрати події централізовано, відповідно SIEM «сліпий»"_.

**Розділ/патерн конспекту:**

- Патерн "Структуроване логування у stdout"
- Сигнали взаємодії: "Логи у форматах JSON, CEF, ECS"
- Принцип "Якщо подія не залишає сліду, який можна перевірити, для системи безпеки її не існує"

**Виправлення:**

```python
import structlog
from uuid import uuid4

logger = structlog.get_logger()

@app.post("/login")
def login(data: LoginRequest, request: Request):
    request_id = str(uuid4())

    logger.info(
        "login_attempt",
        request_id=request_id,
        username=data.username,
        client_ip=request.client.host,
        user_agent=request.headers.get("user-agent")
    )

    if authenticate(data.username, data.password):
        logger.info("login_success", request_id=request_id, username=data.username)
        return {"status": "ok"}

    logger.warning("login_failed", request_id=request_id, username=data.username)
    return {"status": "fail"}
```

---

## Підсумок

| Проблема           | Файл            | Відсутній сигнал      | Порушений принцип        |
| ------------------ | --------------- | --------------------- | ------------------------ |
| Відсутня типізація | main.py         | OpenAPI, Pydantic     | Наявність сигналів       |
| Секрети без Vault  | deployment.yaml | Vault CSI             | Централізований контроль |
| CI без перевірок   | ci.yml          | SBOM, SAST, CVE gates | Secure by Design         |
| Відкрита SG        | main.tf         | OPA policy            | PoLP                     |
| Без SBOM/підпису   | Dockerfile      | Supply chain          | Контроль походження      |
| Без логування      | main.py         | Structured logs       | Спостережуваність        |

---

## Висновок

Проаналізована система архітектурно **"невидима"** для інструментів безпеки. Жоден з компонентів не продукує сигналів, які можна перевірити автоматично:

- **SAST мовчить** — бо немає типізації
- **DAST мовчить** — бо немає OpenAPI
- **Trivy мовчить** — бо немає SBOM
- **SIEM мовчить** — бо немає логів
- **tfsec мовчить** — бо немає OPA policy для блокування

Як зазначено в конспекті: _"Якщо є одне чи два «Ні» — перевірка вже не буде повною. Якщо більше трьох — система архітектурно «невидима» — і ні про яку безпеку вже мови не йде."_

Усі 6 виявлених проблем потребують архітектурних змін, а не просто "фіксів" — потрібно перепроєктувати систему так, щоб вона продукувала сигнали для автоматичної перевірки.
