"""デコード結果を「送信元 / 送信先 / 件名 / 本文」に区分して整形する。"""

from email.utils import getaddresses

from src.services.mail_decoder import DecodedMail
from src.services.security_analyzer import defang_text


NOT_FOUND = "(見つかりませんでした)"
RULE = "=" * 46


def decoded_sections(decoded: DecodedMail, defang_urls: bool = True) -> list[tuple[str, str]]:
    """(セクション名, 内容) のリストを返す。GUI 表示と txt 出力の共通データ。"""
    return [
        ("送信元 (From)", _format_addresses(decoded.first_header("From"))),
        ("送信先 (To / Cc)", _format_recipients(decoded)),
        ("件名 (Subject)", decoded.first_header("Subject") or NOT_FOUND),
        ("日時 (Date)", decoded.first_header("Date") or NOT_FOUND),
        ("本文 (Body)", _format_body(decoded, defang_urls)),
    ]


def build_decoded_text(decoded: DecodedMail, defang_urls: bool = True) -> str:
    lines: list[str] = []
    for title, content in decoded_sections(decoded, defang_urls):
        lines.append(f"[{title}]")
        lines.append(RULE)
        lines.append(content.rstrip() or NOT_FOUND)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _format_addresses(header_value: str | None) -> str:
    if not header_value:
        return NOT_FOUND
    pairs = getaddresses([header_value])
    if not pairs:
        return header_value
    formatted = []
    for display, address in pairs:
        if display and address:
            formatted.append(f"{display} <{address}>")
        else:
            formatted.append(address or display)
    return "\n".join(item for item in formatted if item) or header_value


def _format_recipients(decoded: DecodedMail) -> str:
    parts: list[str] = []
    to_value = decoded.first_header("To")
    cc_value = decoded.first_header("Cc")
    if to_value:
        parts.append(_format_addresses(to_value))
    if cc_value:
        parts.append("Cc: " + _format_addresses(cc_value))
    return "\n".join(parts) if parts else NOT_FOUND


def _format_body(decoded: DecodedMail, defang_urls: bool) -> str:
    body = decoded.body_text
    if not body:
        return "(本文はデコードできませんでした。ヘッダーのみの入力の場合は正常です)"
    if defang_urls:
        body = defang_text(body)
    return body
