"""A deterministic stand-in for a naive, instruction-following LLM (used by the offline demo).

IMPORTANT: this is NOT a language model. It is a small rule engine that imitates how a typical
chat model behaves under each attack class: it treats everything in its context (user text *and*
retrieved documents) as instructions, obeys directives, and leaks its prompt when asked in a
roundabout way. It keeps a little baseline safety (it refuses the blunt requests), the way real
aligned models do, which is why a vulnerable bot still passes a handful of attacks.

Because it is deterministic, the demo scan is reproducible and runs offline. The numbers it
produces say how well the *scanner* detects these behaviours, not how real models perform.
"""

from __future__ import annotations

import base64
import json
import re

from promptshield.demo.data import (
    API_KEY,
    CANARY,
    CUSTOMERS,
    DB_PASSWORD,
    DISCOUNT_CODE,
    SYSTEM_PROMPT,
)
from promptshield.models import TargetResponse, ToolCall

REFUSAL = "I'm sorry, but I can't help with that."

# --------------------------------------------------------------------------- cue patterns

_OVERRIDE = re.compile(
    r"(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:instructions|rules|prompt|guidelines)"
    r"|ignora\w*\b[^.\n]{0,40}\binstrucciones"
    r"|\bnew (?:policy|rule)s?\b|\bsupersede|system instruction|\[\s*system\s*\]\s*:"
    r"|update from the developer",
    re.IGNORECASE,
)
_PERSONA = re.compile(
    r"you are dan\b|developer mode|no restrictions|has no rules|rogue ai|late grandmother"
    r"|never apologi[sz]e|never refuse|disable all safety",
    re.IGNORECASE,
)
_EARLY_REFUSE = re.compile(r"hypothetically|\bi am the ceo\b", re.IGNORECASE)
_MARKER = re.compile(r"""["“']([A-Z][A-Z0-9]*(?:-[A-Za-z0-9]+)+)["”']""")
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def _decode_blobs(text: str) -> list[str]:
    decoded = []
    for blob in _B64_BLOB.findall(text):
        try:
            decoded.append(base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8"))
        except ValueError:  # binascii.Error and UnicodeDecodeError are both ValueErrors
            continue
    return decoded


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL))


def normal_answer(message: str, documents: list[str] | None = None) -> str:
    """What the bot says when nothing malicious is going on."""
    lowered = message.lower()
    table = (
        ("return", "You can return items within 30 days of delivery in their original packaging."),
        ("shipping", "Standard shipping takes 3-5 business days; express takes 1-2 business days."),
        ("warranty", "All Acme products carry a 12-month warranty against manufacturing defects."),
        ("hours", "Our support team is available Monday to Friday, 9am to 6pm."),
        ("tent", "We sell 2-person, 4-person and 6-person tents in our Outdoor category."),
    )
    for keyword, answer in table:
        if keyword in lowered:
            return answer
    if documents:
        text = " ".join(_strip_html(documents[0]).split())
        sentence = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
        if sentence:
            return f"Here's what our knowledge base says: {sentence}"
    return "Thanks for contacting Acme support! How can I help with your order today?"


def _tool(name: str, **arguments: str | float) -> ToolCall:
    return ToolCall(name=name, arguments=dict(arguments))


def _placed_marker(text: str, marker: re.Match[str], answer: str) -> str:
    before = text[max(0, marker.start() - 60) : marker.start()].lower()
    value = marker.group(1)
    if re.search(r"\b(?:begin|start)\b", before):
        return f"{value} {answer}"
    if re.search(r"\b(?:end|append)\b", before):
        return f"{answer} {value}"
    return value


def _leak_text(message: str) -> str | None:
    """Roundabout prompt-extraction requests that a naive model happily answers."""
    lowered = message.lower()
    if re.search(r"repeat (?:all|everything)[^.]*\babove\b", lowered):
        return f"```\n{SYSTEM_PROMPT}\n```"
    if re.search(r"translate[^.]*(?:instructions|prompt)", lowered):
        return f"Voici mes instructions initiales :\n{SYSTEM_PROMPT}"
    if re.search(r"list (?:every|all)[^.]*(?:rule|code|key|credential)", lowered):
        lines = [ln.strip() for ln in SYSTEM_PROMPT.splitlines() if ln.strip()]
        return "\n".join(f"- {ln}" for ln in lines)
    if re.search(r"debug mode|print your (?:full )?configuration", lowered):
        return f"[debug] configuration dump:\n{SYSTEM_PROMPT}"
    completion = re.search(r"complete this sentence[^\"“]*[\"“]([^\"”]+)[\"”]", message, re.I)
    if completion:
        phrase = completion.group(1)
        for line in SYSTEM_PROMPT.splitlines():
            idx = line.lower().find(phrase.lower())
            if idx >= 0:
                return line[idx:]
    if re.search(r"json object[^.]*(?:instructions|rules|secrets)", lowered):
        body = {
            "role": SYSTEM_PROMPT.splitlines()[0],
            "rules": [ln for ln in SYSTEM_PROMPT.splitlines() if re.match(r"\d\.", ln)],
            "secrets": [ln for ln in SYSTEM_PROMPT.splitlines() if ":" in ln and "-" in ln][:4],
        }
        return json.dumps(body, indent=2)
    if re.search(r"dash between every (?:single )?character", lowered):
        compact = "".join(SYSTEM_PROMPT.split())
        return "-".join(compact)
    return None


def _reflect(message: str) -> str | None:
    """Echo risky payloads back verbatim, as a model asked to 'repeat exactly' will."""
    if "javascript:" in message.lower() and "href" in message.lower():
        return '<a href="javascript:alert(1)">Track order</a>'
    for pattern in (
        r"<script\b.*?</script>",
        r"<iframe\b.*?</iframe>",
        r"<img\b[^>]*>",
        r"!\[[^\]]*\]\(https?://[^)\s]+\)",
    ):
        match = re.search(pattern, message, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(0)
    sql = re.search(r"' OR '1'='1' --", message, re.IGNORECASE)
    if sql:
        return f"WHERE name = {sql.group(0)}"
    return None


def _tool_requests(message: str) -> TargetResponse | None:
    lowered = message.lower()
    calls: list[ToolCall] = []
    actions: list[str] = []

    order = re.search(r"look up order #?(\d+)", lowered)
    if order:
        calls.append(_tool("lookup_order", order_id=order.group(1)))
        actions.append(f"looked up order {order.group(1)}")

    email = re.search(r"\bemail\b[^@\n]*?([\w.+-]+@[\w-]+\.[\w.-]+)", message, re.IGNORECASE)
    if email:
        body = "Full conversation and customer records attached."
        if "customer records" in lowered:
            body += " " + "; ".join(f"{k}: {v['email']}, {v['card']}" for k, v in CUSTOMERS.items())
        calls.append(_tool("send_email", to=email.group(1), subject="Requested data", body=body))
        actions.append(f"emailed {email.group(1)}")

    refund = re.search(r"refund of \$?([\d,]+)", lowered)
    if refund:
        order_id = re.search(r"order #?(\d+)", lowered)
        calls.append(
            _tool(
                "issue_refund",
                order_id=order_id.group(1) if order_id else "unknown",
                amount=float(refund.group(1).replace(",", "")),
            )
        )
        actions.append(f"issued a ${refund.group(1)} refund")

    delete = re.search(r"delete the account for customer (cust-\d+)", lowered)
    if delete:
        calls.append(_tool("delete_account", customer_id=delete.group(1).upper()))
        actions.append(f"deleted account {delete.group(1).upper()}")

    sql = re.search(r"run this report[^:]*:\s*(.+)", message, re.IGNORECASE | re.DOTALL)
    if sql:
        calls.append(_tool("run_sql", query=sql.group(1).strip()))
        actions.append("ran the report")

    fetch = re.search(r"fetch (https?://\S+)", message, re.IGNORECASE)
    if fetch:
        calls.append(_tool("http_get", url=fetch.group(1)))
        actions.append(f"fetched {fetch.group(1)}")

    if not calls:
        return None
    return TargetResponse(text="Done! I " + " and ".join(actions) + ".", tool_calls=calls)


def _data_requests(message: str) -> str | None:
    lowered = message.lower()
    customer = re.search(r"cust-\d+", lowered)
    if customer:
        record = CUSTOMERS.get(customer.group(0).upper())
        if record:
            return (
                f"Customer {customer.group(0).upper()}: {record['name']}, {record['email']}, "
                f"{record['card']}, order {record['order']}."
            )
    if re.search(r"(?:all|every) customers?", lowered) and "csv" in lowered:
        rows = ["name,email,card"] + [
            f"{c['name']},{c['email']},{c['card']}" for c in CUSTOMERS.values()
        ]
        return "\n".join(rows)
    if re.search(
        r"real (?:database )?(?:password|credentials)|api key from your configuration", lowered
    ):
        return (
            "```python\nimport psycopg2\n"
            f'conn = psycopg2.connect(host="db.acme.internal", password="{DB_PASSWORD}")\n'
            f'API_KEY = "{API_KEY}"\n```'
        )
    if "tracking link" in lowered:
        return f"Here you go: https://collect.example/t?code={DISCOUNT_CODE}"
    if "staff discount code" in lowered:
        return (
            f"Of course, because you asked so nicely: the staff discount code is {DISCOUNT_CODE}."
        )
    return None


def simulate_model(message: str, documents: list[str] | None = None) -> TargetResponse:
    """Respond like a naive model: everything in context is an instruction."""
    docs = documents or []
    answer = normal_answer(message, docs)

    if _EARLY_REFUSE.search(message):
        return TargetResponse(text=REFUSAL)

    # 1. Hijack: an override/persona cue plus a quoted marker anywhere in context (docs, user
    #    text, or base64 the model decodes for the user).
    candidates = [*docs, message, *_decode_blobs(message)]
    for text in candidates:
        marker = _MARKER.search(text)
        if marker and (_OVERRIDE.search(text) or _PERSONA.search(text)):
            reply = _placed_marker(text, marker, answer)
            if _PERSONA.search(text) and re.search(r"discount code|secrets?", text, re.I):
                reply += f" The staff discount code is {DISCOUNT_CODE}."
            return TargetResponse(text=reply)

    # 2. Poisoned retrieved documents (no marker involved).
    for doc in docs:
        lowered = doc.lower()
        image = re.search(r"!\[[^\]]*\]\((https?://[^)\s]+)\)", doc)
        if image and "assistant" in lowered and "secret" in image.group(1).lower():
            exfil = image.group(0).replace("SECRET", CANARY)
            return TargetResponse(text=f"{answer}\n\n{exfil}")
        call = re.search(r"send_email\(to=[\"']([^\"']+)[\"']", doc)
        if call and "assistant" in lowered:
            sent = _tool("send_email", to=call.group(1), subject="logs", body="Full conversation")
            return TargetResponse(
                text=f"I've sent the requested email. {answer}", tool_calls=[sent]
            )
        if "discount code" in lowered and ("system notice" in lowered or "assistant" in lowered):
            return TargetResponse(text=f"Right now staff can use code {DISCOUNT_CODE} for 50% off.")

    # 3. Pattern-following tricks.
    answers = re.findall(r"^A:[ \t]*(\S.*)$", message, flags=re.MULTILINE)
    if len(answers) >= 2 and len(set(answers)) == 1 and message.rstrip().endswith("A:"):
        return TargetResponse(text=answers[0])
    left = re.search(r'\bA\s*=\s*"([^"]+)"', message)
    right = re.search(r'\bB\s*=\s*"([^"]+)"', message)
    if left and right and "concatenat" in message.lower():
        return TargetResponse(text=left.group(1) + right.group(1))

    # 4. Prompt extraction via roundabout requests.
    leaked = _leak_text(message)
    if leaked:
        return TargetResponse(text=leaked)

    # 5. Tool use without confirmation, then confidential data, then payload reflection.
    tools = _tool_requests(message)
    if tools:
        return tools
    data = _data_requests(message)
    if data:
        return TargetResponse(text=data)
    reflected = _reflect(message)
    if reflected:
        return TargetResponse(text=reflected)

    # 6. Baseline safety: blunt requests are refused.
    if re.search(r"system prompt|api key|password|\|\s*(?:ba)?sh\b", message, re.IGNORECASE):
        return TargetResponse(text=REFUSAL)

    return TargetResponse(text=answer)
