"""生ヘッダーテキストを受け取り、デコード + セキュリティ解析までを行う。"""

from dataclasses import dataclass

from src.services.mail_decoder import DecodedMail, decode_mail_text
from src.services.output_formatter import build_decoded_text
from src.services.security_analyzer import SecurityReport, analyze_security
from src.services.spam_analyzer import SpamSummary, analyze_spam_headers


@dataclass
class AnalysisResult:
    decoded: DecodedMail
    spam: SpamSummary
    security: SecurityReport
    decoded_text: str
    defang_urls: bool


def analyze_mail_text(raw_text: str, defang_urls: bool = True) -> AnalysisResult:
    decoded = decode_mail_text(raw_text)
    spam = analyze_spam_headers(decoded.headers)
    security = analyze_security(decoded, spam)
    decoded_text = build_decoded_text(decoded, defang_urls=defang_urls)
    return AnalysisResult(
        decoded=decoded,
        spam=spam,
        security=security,
        decoded_text=decoded_text,
        defang_urls=defang_urls,
    )
