from collections.abc import Iterator
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header
from email.message import Message
from email.parser import BytesParser, Parser
import html
import re


CHARSET_FALLBACKS = ("utf-8", "iso-2022-jp", "cp932", "latin-1")


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int | None = None


@dataclass
class DecodedMail:
    headers: list[tuple[str, str]]
    body_text: str
    body_html: str
    body_content_type: str
    attachments: list[AttachmentInfo] = field(default_factory=list)

    def first_header(self, name: str) -> str | None:
        target = name.lower()
        for header_name, value in self.headers:
            if header_name.lower() == target:
                return value
        return None

    def all_headers(self, name: str) -> list[str]:
        target = name.lower()
        return [value for header_name, value in self.headers if header_name.lower() == target]


def decode_mail(raw_message: bytes) -> DecodedMail:
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    return _build_decoded_mail(message, prefer_text_payload=False)


def decode_mail_text(raw_text: str) -> DecodedMail:
    normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n").removeprefix("\ufeff")
    message = Parser(policy=policy.default).parsestr(normalized)
    return _build_decoded_mail(message, prefer_text_payload=True)


def _build_decoded_mail(message: Message, prefer_text_payload: bool) -> DecodedMail:
    headers = [(name, _decode_value(str(value))) for name, value in message.items()]
    body_text, body_html, body_content_type = _extract_body(
        message, prefer_text_payload=prefer_text_payload
    )
    return DecodedMail(
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        body_content_type=body_content_type,
        attachments=_extract_attachments(message),
    )


def _decode_value(value: str) -> str:
    decoded_chunks: list[str] = []
    try:
        chunks = decode_header(value)
    except Exception:
        return value.strip()

    for chunk, charset in chunks:
        if isinstance(chunk, bytes):
            decoded_chunks.append(_decode_bytes(chunk, charset))
        else:
            decoded_chunks.append(chunk)
    return "".join(decoded_chunks).strip()


def _extract_body(message: Message, prefer_text_payload: bool = False) -> tuple[str, str, str]:
    html_part = _find_text_part(message, "text/html")
    html_text = (
        _decode_part_text(html_part, prefer_text_payload=prefer_text_payload)
        if html_part
        else ""
    )

    plain_part = _find_text_part(message, "text/plain")
    if plain_part:
        return (
            _decode_part_text(plain_part, prefer_text_payload=prefer_text_payload),
            html_text,
            "text/plain",
        )

    if html_part:
        return _html_to_text(html_text), html_text, "text/html"

    return "", "", ""


def _find_text_part(message: Message, target_content_type: str) -> Message | None:
    for part in _iter_inline_leaf_parts(message):
        if part.get_content_type() == target_content_type:
            return part
    return None


def _iter_inline_leaf_parts(message: Message) -> Iterator[Message]:
    """添付コンテナ配下へ降りず、外側メールの本文候補だけを列挙する。"""
    if message.get_content_disposition() == "attachment" or message.get_filename():
        return
    if not message.is_multipart():
        yield message
        return

    payload = message.get_payload()
    if not isinstance(payload, list):
        return
    for part in payload:
        yield from _iter_inline_leaf_parts(part)


def _extract_attachments(message: Message) -> list[AttachmentInfo]:
    attachments: list[AttachmentInfo] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        if part.get_content_disposition() != "attachment" and not filename:
            continue
        payload = part.get_payload(decode=True)
        attachments.append(
            AttachmentInfo(
                filename=_decode_value(filename) if filename else "(名称不明)",
                content_type=part.get_content_type(),
                size=len(payload) if payload is not None else None,
            )
        )
    return attachments


def _decode_part_text(part: Message, prefer_text_payload: bool = False) -> str:
    raw_payload = part.get_payload()
    transfer_encoding = (part.get("Content-Transfer-Encoding") or "").strip().lower()
    if (
        prefer_text_payload
        and isinstance(raw_payload, str)
        and transfer_encoding not in ("base64", "quoted-printable")
    ):
        return _normalize_newline(raw_payload).strip()

    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None

    if payload is None:
        if isinstance(raw_payload, str):
            return _normalize_newline(raw_payload).strip()
        return ""

    charset = part.get_content_charset()
    text = _decode_bytes(payload, charset)
    return _normalize_newline(text).strip()


def _decode_bytes(data: bytes, charset: str | None) -> str:
    encodings = [charset] if charset else []
    encodings.extend(CHARSET_FALLBACKS)

    for encoding in encodings:
        if not encoding:
            continue
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue

    return data.decode("utf-8", errors="replace")


def _normalize_newline(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _html_to_text(html_body: str) -> str:
    without_script = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html_body)
    with_breaks = re.sub(r"(?i)<br\s*/?>", "\n", without_script)
    with_blocks = re.sub(r"(?i)</(p|div|li|tr|h1|h2|h3|h4|h5|h6)>", "\n", with_breaks)
    without_tags = re.sub(r"(?s)<[^>]+>", "", with_blocks)
    decoded = html.unescape(without_tags)
    cleaned_lines = [line.strip() for line in _normalize_newline(decoded).split("\n")]
    return "\n".join(line for line in cleaned_lines if line)
