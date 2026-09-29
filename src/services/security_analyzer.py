"""メールヘッダー・本文のセキュリティ解析(バランス重視の重み付け)。

判定方針: 「送信ドメインが認証で裏付けられているか」を軸に据える。
- DMARC 認証が通っている(= From ドメインが本物と裏付けられている)メールは、
  よほど強い脅威(リンク先すり替え・マルウェア添付・スクリプト等)がない限り
  過剰に警告しない。
- 認証がない/失敗しているメールでは、送信者アドレスの不審さ(ランダムな英数字、
  公式に酷似したドメイン、名義とアドレスの不一致)・HTML 経由の攻撃・添付ファイル・
  誘導文言などのリスクを積み上げて評価する。
- なりすまし確定級の単独シグナル(DMARC 失敗、表示 URL とリンク先の相違、
  ブランド偽装ドメイン、実行ファイル添付、本文内スクリプトなど)は 1 件で「高」。

こうして「厳しすぎず・緩すぎず」を狙う。

ネットワークアクセスは一切行わず、貼り付けられたテキストだけを
ローカルで解析する(URL への問い合わせや DNS 参照はしない)。
"""

from dataclasses import dataclass, field
from email.utils import parseaddr, parsedate_to_datetime
import html
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from src.services.geoip import GeoInfo, describe_ip
from src.services.mail_decoder import DecodedMail
from src.services.spam_analyzer import SpamSummary


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}
# high 1 件で「高」。medium は 1 件で「低」、2 件で「中」、3 件で「高」。
SEVERITY_SCORE = {"high": 40, "medium": 15, "low": 5, "info": 0, "ok": 0}
SEVERITY_LABEL = {
    "high": "危険",
    "medium": "注意",
    "low": "軽微",
    "info": "情報",
    "ok": "OK",
}

# 悪用が突出して多い TLD
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "cam", "rest",
    "click", "buzz", "monster", "quest", "zip", "mov", "stream",
    "download", "racing", "loan", "men", "cyou", "sbs", "bond", "cfd",
    "kim", "country", "party", "gdn", "work", "date", "wang",
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at", "tiny.cc",
    "x.gd", "urx.red", "ur0.link", "00m.in", "u.to", "v.gd", "lin.ee",
    "onl.la", "onl.sc", "qr.paps.jp", "bit.do", "s.id", "t.ly", "shorturl.asia",
    "rebrandly.com", "clck.ru", "vk.cc", "tr.im", "chilp.it", "soo.gd",
    "clik.cc", "shorte.st", "adf.ly", "j.mp", "b.link", "short.io",
    "gg.gg", "5g.hk", "picz.in.th", "reurl.cc", "0rz.tw", "ppt.cc",
    "muya.jp", "1lnk.net", "kutt.it", "short.gy", "shrturl.app",
}
# 誰でも無料でページを公開でき、フィッシングに悪用されやすいホスティング
FREE_HOSTING_SUFFIXES = (
    "pages.dev", "web.app", "firebaseapp.com", "workers.dev", "r2.dev",
    "weebly.com", "wixsite.com", "blogspot.com", "glitch.me", "repl.co",
    "replit.app", "netlify.app", "vercel.app", "herokuapp.com", "github.io",
    "gitlab.io", "surge.sh", "000webhostapp.com", "byethost.com", "wordpress.com",
    "webnode.jp", "jimdofree.com", "amebaownd.com", "storage.googleapis.com",
    "s3.amazonaws.com", "blob.core.windows.net", "translate.goog",
    "sharepoint.com", "myftp.org", "duckdns.org", "form.run", "notion.site",
    "backblazeb2.com", "cdn.digitaloceanspaces.com",
)
# ダイナミック DNS(攻撃者が使い捨て的に使う)
DYNAMIC_DNS_SUFFIXES = (
    "no-ip.org", "no-ip.com", "ddns.net", "duckdns.org", "hopto.org",
    "zapto.org", "sytes.net", "serveo.net", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "loca.lt", "localtunnel.me", "dynu.com", "myddns.me",
)
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "pif", "com", "bat", "cmd", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "hta", "lnk", "jar", "msi", "ps1", "iso", "img", "vhd",
    "chm", "cpl", "reg", "msc", "application", "gadget", "inf", "ace",
}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "sldm", "xlam", "xll"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "lzh", "cab", "tar", "gz", "arj"}
# 二重拡張子で本当の実行ファイルを隠す手口 (invoice.pdf.exe など)
DOCUMENT_LOOKALIKE_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "png", "txt"}

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.co.jp", "yahoo.com", "ymail.ne.jp",
    "outlook.com", "outlook.jp", "hotmail.com", "hotmail.co.jp", "live.jp",
    "live.com", "msn.com", "icloud.com", "me.com", "mac.com", "aol.com",
    "mail.com", "gmx.com", "gmx.net", "proton.me", "protonmail.com",
    "docomo.ne.jp", "ezweb.ne.jp", "au.com", "softbank.ne.jp", "i.softbank.jp",
    "excite.co.jp", "nifty.com", "so-net.ne.jp", "mail.ru", "yandex.com",
    "qq.com", "163.com", "126.com", "sina.com",
}

# 表示名がこれらを含む場合、金融機関・公的機関などのなりすましを疑う。
CORPORATE_DISPLAY_TOKENS = (
    "銀行", "カード", "公式", "事務局", "カスタマー", "セキュリティセンター",
    "税務", "市役所", "県庁", "年金", "国税", "信用金庫", "証券", "支払",
    "bank", "card", "paypal", "amazon", "rakuten", "apple", "microsoft",
)

# よく騙られるブランドと正規ドメイン(なりすまし検出用)
BRAND_OFFICIAL_DOMAINS: dict[str, tuple[str, ...]] = {
    r"amazon|アマゾン": ("amazon.co.jp", "amazon.com", "amazon.jp", "amazonses.com"),
    r"rakuten|楽天": ("rakuten.co.jp", "rakuten.com", "rakuten-bank.co.jp", "rakuten-card.co.jp"),
    r"apple|icloud|アップル": ("apple.com", "icloud.com", "me.com", "mac.com"),
    r"yamato|ヤマト|クロネコ": ("kuronekoyamato.co.jp", "yamato-transport.com", "yamato-hd.co.jp"),
    r"sagawa|佐川": ("sagawa-exp.co.jp",),
    r"japanpost|日本郵便|ゆうパック|ゆうちょ": ("japanpost.jp", "jp-bank.japanpost.jp", "post.japanpost.jp"),
    r"etc利用照会|etcマイレージ": ("ml.etc-meisai.jp", "smile-etc.jp"),
    r"smbc|三井住友": ("smbc.co.jp", "smbc-card.com", "vpass.ne.jp", "smbc-finance.co.jp"),
    r"mufg|三菱ufj": ("mufg.jp", "bk.mufg.jp", "cr.mufg.jp"),
    r"mizuho|みずほ": ("mizuhobank.co.jp", "mizuho-fg.co.jp"),
    r"jcb": ("jcb.co.jp", "jcb.jp"),
    r"aeon|イオン": ("aeon.co.jp", "aeon.jp", "aeonbank.co.jp", "aeoncard.co.jp"),
    r"paypal|ペイパル": ("paypal.com", "paypal.jp"),
    r"paypay|ペイペイ": ("paypay.ne.jp", "paypay-bank.co.jp", "paypay-card.co.jp"),
    r"mercari|メルカリ": ("mercari.com", "mercari.jp"),
    r"国税庁|e-tax|イータックス": ("nta.go.jp",),
    r"eki-net|えきねっと": ("eki-net.com", "jreast.co.jp"),
    r"docomo|ドコモ|d払い": ("docomo.ne.jp", "nttdocomo.co.jp", "smt.docomo.ne.jp", "dpoint.jp"),
    r"softbank|ソフトバンク": ("softbank.jp", "softbank.ne.jp", "i.softbank.jp"),
    r"netflix|ネットフリックス": ("netflix.com",),
    r"microsoft|マイクロソフト": ("microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com"),
    r"google|グーグル": ("google.com", "googlemail.com", "accounts.google.com"),
    r"nintendo|任天堂": ("nintendo.co.jp", "nintendo.com", "accounts.nintendo.com"),
    r"epos|エポス": ("eposcard.co.jp",),
    r"saison|セゾン": ("saisoncard.co.jp",),
}

URGENCY_KEYWORDS = (
    # 日本語
    "緊急", "至急", "重要なお知らせ", "アカウントが停止", "アカウント停止",
    "利用停止", "ご利用を制限", "利用制限", "確認してください", "ご確認ください",
    "本人確認", "パスワードの再設定", "パスワード再設定", "セキュリティ警告",
    "不正アクセス", "不正利用", "異常なログイン", "不審なログイン",
    "お支払い", "未払い", "未納", "滞納", "還付金",
    "当選", "24時間以内", "48時間以内", "本日中", "有効期限",
    "更新してください", "ロックされ", "凍結", "解除", "認証コード",
    "お荷物", "再配達", "配達できません", "不在のため",
    "お届けできません", "住所が不明", "こちらをクリック",
    "以下のリンク", "無料プレゼント",
    # 英語
    "verify your account", "verify now", "verify identity", "urgent",
    "suspended", "suspend", "confirm your", "password reset",
    "security alert", "unusual activity", "unusual sign-in",
    "payment required", "act now", "final notice", "click here",
    "your package", "delivery failed", "account locked",
    "update your information", "billing problem",
)

# 内容ベースのスパム判定用キーワード(緊急性=URGENCY とは別に、
# 金銭・射幸心・アダルト・広告系を集めたもの)
SPAM_KEYWORDS = (
    # 金銭・射幸
    "当選", "高額", "稼げる", "稼ぐ", "副業", "儲か", "現金", "億円", "万円",
    "ギフト券", "ポイント進呈", "ポイントプレゼント", "換金", "投資", "暗号資産",
    "ビットコイン", "仮想通貨", "配当", "利回り", "キャッシュバック", "融資",
    "借入", "ローン", "後払い", "情報商材", "権利収入", "不労所得", "在宅ワーク",
    # 射幸・広告
    "激安", "格安", "最安", "特別価格", "限定価格", "今だけ", "先着", "抽選",
    "完全無料", "登録無料", "無料体験", "無料プレゼント", "もれなく",
    # 出会い・アダルト
    "出会い", "マッチング", "アダルト", "秘密", "友達募集", "サポート致します",
    # 英語スパム
    "viagra", "cialis", "casino", "lottery", "winner", "you won",
    "make money", "work from home", "weight loss", "free gift",
    "get rich", "million dollars", "crypto", "investment opportunity",
    "hot singles", "adult", "prize", "gift card",
)

URL_RE = re.compile(
    r"(?:https?|hxxps?)://(?:\[[0-9A-Za-z:.%_-]+\][^\s<>\"'()】]*|[^\s<>\"'()\]】]+)",
    re.IGNORECASE,
)
BARE_DOMAIN_RE = re.compile(
    r"(?<![@\w.-])((?:www\.)?(?:[a-z0-9-]+\.)+[a-z]{2,63}"
    r"(?::\d{1,5})?(?:/[^\s<>\"'()]*)?)",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
IPV6_BRACKET_RE = re.compile(
    r"\[(?:IPv6:)?([0-9A-Fa-f]*:[0-9A-Fa-f:.]+(?:%[0-9A-Za-z_.-]+)?)\]",
    re.IGNORECASE,
)
EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
DOMAIN_IN_TEXT_RE = re.compile(r"\b((?:[\w-]+\.)+(?:com|net|org|jp|co\.jp|ne\.jp|or\.jp|info|biz|shop|xyz|top))\b", re.IGNORECASE)
ANCHOR_RE = re.compile(
    r"""<a\s[^>]*href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>(.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)

# HTML 経由の攻撃検出用
SCRIPT_RE = re.compile(r"<script\b", re.IGNORECASE)
IFRAME_RE = re.compile(r"<iframe\b", re.IGNORECASE)
EXTERNAL_FORM_RE = re.compile(r"""<form\b[^>]*action\s*=\s*["']?\s*(?:https?:)?//""", re.IGNORECASE)
META_REFRESH_RE = re.compile(r"""<meta\b[^>]*http-equiv\s*=\s*["']?\s*refresh""", re.IGNORECASE)
EVENT_HANDLER_RE = re.compile(r"""\son(?:load|click|error|mouseover|submit)\s*=""", re.IGNORECASE)
JS_URI_RE = re.compile(r"""(?:href|src)\s*=\s*["']?\s*javascript:""", re.IGNORECASE)

# ホモグリフ / 文字置換の正規化(0→o, 1→l など)
_HOMOGLYPH_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g", "$": "s", "@": "a", "|": "l",
})
_VOWELS = set("aeiou")


@dataclass
class Finding:
    severity: str  # high / medium / low / info / ok
    title: str
    detail: str = ""


@dataclass
class AuthResults:
    spf: str | None = None
    dkim: str | None = None
    dkim_domain: str | None = None
    dmarc: str | None = None
    dmarc_domain: str | None = None
    dmarc_policy: str | None = None
    source: str | None = None
    ignored_sources: list[str] = field(default_factory=list)


@dataclass
class ReceivedHop:
    position: int
    from_host: str | None
    from_comment: str | None
    ip: str | None
    ip_is_private: bool | None
    by_host: str | None
    date: str | None
    raw: str
    geo: GeoInfo | None = None


@dataclass
class OriginGuess:
    host: str | None
    ip: str | None
    date: str | None
    hop_position: int


@dataclass
class UrlInfo:
    url: str
    host: str
    flags: list[str] = field(default_factory=list)
    high_risk: bool = False


@dataclass
class SecurityReport:
    risk_score: int
    risk_level: str
    findings: list[Finding]
    auth: AuthResults
    hops: list[ReceivedHop]
    origin: OriginGuess | None
    urls: list[UrlInfo]
    from_address: str | None
    from_display: str | None


def analyze_security(decoded: DecodedMail, spam: SpamSummary) -> SecurityReport:
    findings: list[Finding] = []

    hops = _parse_received_chain(decoded)
    origin = _guess_origin(hops)
    has_route = bool(hops)

    trusted_receiver = _trusted_receiver_from_hops(hops)
    auth = _parse_auth_results(decoded, trusted_receiver)
    # From ドメインが本物と裏付けられているか(なりすまし判定の軸)
    from_display, from_addr = parseaddr(decoded.first_header("From") or "")
    from_domain = _domain_of(from_addr)
    strong_auth = (
        auth.dmarc == "pass"
        and _same_org_domain(auth.dmarc_domain or "", from_domain)
    ) or (
        auth.spf == "pass" and auth.dkim == "pass" and _same_org_domain(auth.dkim_domain or "", from_domain)
    )

    findings.extend(_header_structure_findings(decoded))
    findings.extend(_auth_findings(auth, has_route, from_domain))
    findings.extend(_sender_findings(decoded, from_display, from_addr, has_route, strong_auth))
    findings.extend(_impersonation_findings(from_display, from_addr, strong_auth))

    findings.extend(_route_findings(hops, origin))
    findings.extend(_date_consistency_findings(decoded, hops))

    urls = _extract_urls(decoded)
    findings.extend(_url_findings(urls))
    findings.extend(_anchor_mismatch_findings(decoded))
    findings.extend(_html_threat_findings(decoded))

    findings.extend(_keyword_findings(decoded))
    findings.extend(_content_spam_findings(decoded, urls))
    findings.extend(_body_format_findings(decoded))
    findings.extend(_attachment_findings(decoded))
    findings.extend(_spam_findings(spam))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    score = min(100, sum(SEVERITY_SCORE.get(f.severity, 0) for f in findings))

    return SecurityReport(
        risk_score=score,
        risk_level=_risk_level(score),
        findings=findings,
        auth=auth,
        hops=hops,
        origin=origin,
        urls=urls,
        from_address=from_addr or None,
        from_display=from_display or None,
    )


def _header_structure_findings(decoded: DecodedMail) -> list[Finding]:
    from_headers = decoded.all_headers("From")
    if len(from_headers) <= 1:
        return []
    return [
        Finding(
            "high",
            "From ヘッダーが複数あり差出人を一意に判定できません",
            f"From ヘッダーが {len(from_headers)} 件あります。メールソフトごとに異なる"
            "差出人を表示させるヘッダー曖昧化攻撃の可能性があるため、信頼しないでください。",
        )
    ]


def _risk_level(score: int) -> str:
    if score >= 40:
        return "高"
    if score >= 18:
        return "中"
    if score >= 7:
        return "低"
    return "問題なし"


# --- 送信ドメイン認証 -------------------------------------------------


def _trusted_receiver_from_hops(hops: list[ReceivedHop]) -> str | None:
    """受信側が付与したとみなせる最上段のホスト名を信頼基点にする。"""
    for hop in hops:
        candidate = (hop.by_host or "").lower().rstrip(".")
        if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", candidate):
            return candidate
        # Gmail が付ける IPv6 風の内部配送 ID はホスト名ではないため読み飛ばす。
        # それ以外の単一名・欠落は境界を特定できないので、下位ホップを信頼しない。
        if ":" not in candidate:
            return None
    return None


def _parse_auth_results(decoded: DecodedMail, trusted_receiver: str | None) -> AuthResults:
    auth = AuthResults()
    for value in decoded.all_headers("Authentication-Results"):
        normalized = " ".join(value.split())
        source = normalized.split(";", 1)[0].strip().lower().rstrip(".")
        if not source or not trusted_receiver or not _same_org_domain(source, trusted_receiver):
            ignored = source or "(発行元不明)"
            if ignored not in auth.ignored_sources:
                auth.ignored_sources.append(ignored)
            continue
        auth.source = source
        match = re.search(r"\bspf=([A-Za-z0-9]+)", normalized)
        auth.spf = match.group(1).lower() if match else None
        match = re.search(r"\bdkim=([A-Za-z0-9]+)", normalized)
        auth.dkim = match.group(1).lower() if match else None
        match = re.search(r"\bheader\.d=([\w.-]+)", normalized)
        auth.dkim_domain = match.group(1).lower() if match else None
        match = re.search(r"\bdmarc=([A-Za-z0-9]+)", normalized)
        auth.dmarc = match.group(1).lower() if match else None
        match = re.search(r"\bheader\.from=([\w.-]+)", normalized)
        auth.dmarc_domain = match.group(1).lower().rstrip(".") if match else None
        match = re.search(r"\bp=([A-Za-z]+)", normalized)
        auth.dmarc_policy = match.group(1).lower() if match else None
        # 最上段の一致ヘッダーだけが受信境界で追加されたとみなせる。
        # 下位の同じ authserv-id は送信者が注入できるため、結果を補完させない。
        break
    return auth


def _auth_findings(
    auth: AuthResults, has_route: bool, from_domain: str
) -> list[Finding]:
    findings: list[Finding] = []
    if auth.ignored_sources:
        findings.append(
            Finding(
                "info",
                "信頼境界外の認証結果ヘッダーを判定から除外しました",
                "発行元: " + ", ".join(auth.ignored_sources)
                + "。受信サーバーと一致しない Authentication-Results は送信者が偽造できるため、"
                "SPF/DKIM/DMARC の成功根拠には使用しません。",
            )
        )

    if auth.dmarc == "pass" and not auth.dmarc_domain:
        findings.append(
            Finding(
                "medium",
                "DMARC 認証対象ドメインを確認できません",
                "DMARC は pass と記録されていますが、照合対象の header.from がありません。"
                "表示上の差出人ドメインと一致することを確認できないため、安全な認証成功とは扱いません。",
            )
        )
    elif (
        auth.dmarc == "pass"
        and auth.dmarc_domain
        and from_domain
        and not _same_org_domain(auth.dmarc_domain, from_domain)
    ):
        findings.append(
            Finding(
                "high",
                "DMARC 認証対象ドメインが差出人と一致しません",
                f"認証結果は「{auth.dmarc_domain}」を pass としていますが、"
                f"表示上の差出人ドメインは「{from_domain}」です。複数の From ヘッダーや"
                "不正な認証結果を利用した偽装の可能性があるため、安全な認証成功とは扱いません。",
            )
        )

    if auth.spf is None and auth.dkim is None and auth.dmarc is None:
        if has_route:
            return findings + [
                Finding(
                    "medium",
                    "送信ドメイン認証(SPF/DKIM/DMARC)が一切ありません",
                    "配送経路はあるのに認証結果がまったく記録されていません。昨今の正規メールは"
                    "ほぼ必ず何らかの認証を通過します。差出人が本物である裏付けが無い状態のため、"
                    "本文のリンクや添付は特に慎重に扱ってください。",
                )
            ]
        return findings + [
            Finding(
                "info",
                "送信ドメイン認証の結果が見つかりません",
                "ヘッダーの一部のみが入力されているため、認証結果を判定できません。"
                "「メッセージのソース」全体を貼り付けると精度が上がります。",
            )
        ]

    any_pass = "pass" in (auth.spf, auth.dkim, auth.dmarc)
    absent_severity = "info" if any_pass else "low"
    return findings + [
        _spf_finding(auth.spf, auth.dkim, absent_severity),
        _dkim_finding(auth.dkim, absent_severity),
        _dmarc_finding(auth.dmarc, absent_severity),
    ]


def _spf_finding(spf: str | None, dkim: str | None, absent_severity: str) -> Finding:
    if spf == "pass":
        return Finding("ok", "SPF 認証: pass", "SPF 認証に成功しています。")
    if spf in ("fail", "softfail"):
        if dkim == "pass":
            return Finding(
                "low",
                f"SPF 認証: {spf}",
                "SPF は失敗していますが DKIM 署名は有効です。メール転送や"
                "メーリングリスト経由でよく起こる正常な状態の可能性があります。",
            )
        return Finding(
            "medium",
            f"SPF 認証: {spf}",
            "送信元が差出人ドメインの正規サーバーである確証が得られていません。"
            "なりすましの可能性があります。",
        )
    return Finding(
        absent_severity,
        f"SPF 認証: {spf or '記録なし'}",
        "SPF による送信元の裏付けが得られていません。",
    )


def _dkim_finding(dkim: str | None, absent_severity: str) -> Finding:
    if dkim == "pass":
        return Finding("ok", "DKIM 認証: pass", "DKIM 署名が有効です(本文の改ざんなし)。")
    if dkim == "fail":
        return Finding(
            "medium",
            "DKIM 認証: fail",
            "DKIM 署名の検証に失敗しています。本文が改ざんされたか、"
            "正規の署名がない可能性があります。",
        )
    return Finding(
        absent_severity,
        f"DKIM 認証: {dkim or '記録なし'}",
        "DKIM 署名による裏付けが得られていません。小規模な送信者では"
        "未署名も珍しくありません。",
    )


def _dmarc_finding(dmarc: str | None, absent_severity: str) -> Finding:
    if dmarc == "pass":
        return Finding("ok", "DMARC 認証: pass", "DMARC 認証に成功しています。")
    if dmarc in ("fail", "quarantine", "reject"):
        return Finding(
            "high",
            f"DMARC 認証: {dmarc}",
            "DMARC 認証に失敗しています。差出人アドレス(From)が偽装されている"
            "可能性が高い、強いなりすましの兆候です。",
        )
    return Finding(
        absent_severity,
        f"DMARC 認証: {dmarc or '記録なし'}",
        "DMARC ポリシーによる裏付けが得られていません。",
    )


# --- 差出人まわりの整合性 ---------------------------------------------


def _sender_findings(
    decoded: DecodedMail,
    from_display: str,
    from_addr: str,
    has_route: bool,
    strong_auth: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = _domain_of(from_addr)

    if not from_addr:
        findings.append(Finding("info", "From ヘッダーが見つかりません"))
        return findings

    if "xn--" in from_domain:
        findings.append(
            Finding(
                "high",
                "差出人ドメインに Punycode (xn--) が含まれています",
                f"From ドメイン「{from_domain}」は国際化ドメインの内部表現を含みます。"
                "有名ドメインに似せた偽装ドメインでよく使われる手口です。",
            )
        )
    elif from_domain and not from_domain.isascii():
        findings.append(
            Finding(
                "high",
                "差出人ドメインに非 ASCII 文字が含まれています",
                f"From ドメイン「{from_domain}」に全角文字などが含まれています。"
                "見た目を似せた偽装ドメインの可能性があります。",
            )
        )

    # 表示名に別のメールアドレスが埋め込まれている
    display_emails = EMAIL_IN_TEXT_RE.findall(from_display or "")
    embedded_mismatch = False
    for shown in display_emails:
        if _domain_of(shown) != from_domain:
            embedded_mismatch = True
            findings.append(
                Finding(
                    "high",
                    "表示名に別のメールアドレスが埋め込まれています",
                    f"表示名には「{shown}」と書かれていますが、実際の差出人は"
                    f"「{from_addr}」です。差出人を誤認させる典型的な手口です。",
                )
            )
            break

    # 表示名にドメインらしき文字列があり、アドレスのドメインと食い違う
    if not embedded_mismatch and from_domain:
        for shown_domain in DOMAIN_IN_TEXT_RE.findall(from_display or ""):
            shown_domain = shown_domain.lower()
            if not _same_org_domain(shown_domain, from_domain):
                findings.append(
                    Finding(
                        "medium",
                        "差出人名義とアドレスのドメインが一致しません",
                        f"表示名は「{shown_domain}」を名乗っていますが、実際の送信ドメインは"
                        f"「{from_domain}」です。",
                    )
                )
                break

    # 金融機関・公的機関を名乗るフリーメール(強い偽装兆候)
    if from_domain in FREEMAIL_DOMAINS and _looks_corporate(from_display):
        findings.append(
            Finding(
                "high",
                "組織を名乗る差出人がフリーメールを使用しています",
                f"表示名「{from_display}」に対して、実際の差出人はフリーメール"
                f"({from_domain})です。銀行・カード会社・公的機関などが重要な通知を"
                "フリーメールから送ることはまずなく、なりすましの可能性が高いです。",
            )
        )

    # ランダムな英数字のアドレス(認証済みなら自動送信の可能性が高いので対象外)
    if not strong_auth and from_addr:
        local_part = from_addr.split("@", 1)[0]
        if _looks_random(local_part):
            findings.append(
                Finding(
                    "medium",
                    "差出人アドレスがランダムな英数字です",
                    f"「{from_addr}」のアカウント名が機械的に生成されたような文字列です。"
                    "使い捨てアドレスを使ったばらまき型メールでよく見られます。",
                )
            )
        random_label = _random_domain_label(from_domain)
        if random_label:
            findings.append(
                Finding(
                    "medium",
                    "差出人ドメインがランダムな文字列です",
                    f"ドメイン「{from_domain}」に意味を成さない文字列が含まれます。"
                    "使い捨ての攻撃用ドメインの可能性があります。",
                )
            )

    # 差出人ドメインが悪用の多い TLD
    from_tld = from_domain.rsplit(".", 1)[-1].lower() if "." in from_domain else ""
    if from_tld in SUSPICIOUS_TLDS:
        findings.append(
            Finding(
                "medium",
                f"差出人ドメインが悪用されやすい TLD (.{from_tld}) です",
                f"「{from_domain}」は迷惑メールで多用される TLD を使っています。",
            )
        )

    # Reply-To がフリーメールへ誘導
    reply_to = parseaddr(decoded.first_header("Reply-To") or "")[1]
    reply_domain = _domain_of(reply_to)
    if reply_domain and reply_domain != from_domain:
        if reply_domain in FREEMAIL_DOMAINS and from_domain not in FREEMAIL_DOMAINS:
            findings.append(
                Finding(
                    "medium",
                    "返信先 (Reply-To) がフリーメールに設定されています",
                    f"差出人は「{from_domain}」ですが、返信先は「{reply_to}」です。"
                    "返信を攻撃者のフリーメールに誘導する手口の可能性があります。",
                )
            )
        else:
            findings.append(
                Finding(
                    "info",
                    "Reply-To が From と異なるドメインです",
                    f"返信先は「{reply_to}」です。問い合わせ窓口の分離など正規の"
                    "運用でもよく見られます。",
                )
            )

    message_id = decoded.first_header("Message-ID") or ""
    if not message_id and has_route:
        findings.append(
            Finding(
                "low",
                "Message-ID ヘッダーがありません",
                "多くの正規メールサーバーは Message-ID を付与します。簡易な"
                "送信ツールから送られた可能性があります。",
            )
        )

    return findings


def _looks_corporate(display_name: str) -> bool:
    if not display_name:
        return False
    lowered = display_name.lower()
    return any(token.lower() in lowered for token in CORPORATE_DISPLAY_TOKENS)


def _looks_random(token: str) -> bool:
    """アカウント名やラベルが機械生成のランダム文字列に見えるか。"""
    t = re.sub(r"[^a-z0-9]", "", token.lower())
    if len(t) < 8:
        return False
    letters = [c for c in t if c.isalpha()]
    # 母音が極端に少ない子音の羅列(例: xkjqnf)
    if len(letters) >= 6:
        vowels = sum(c in _VOWELS for c in letters)
        if vowels / len(letters) < 0.20:
            return True
    # 英字と数字が頻繁に交互(例: a8f7g2h9)= ランダム生成の特徴
    if any(c.isdigit() for c in t) and any(c.isalpha() for c in t):
        transitions = sum(1 for a, b in zip(t, t[1:]) if a.isdigit() != b.isdigit())
        if transitions >= len(t) * 0.6:
            return True
    return False


def _random_domain_label(domain: str) -> str | None:
    labels = [label for label in domain.split(".") if label]
    for label in sorted(labels[:-1], key=len, reverse=True):
        if _looks_random(label):
            return label
    return None


def _impersonation_findings(from_display: str, from_addr: str, strong_auth: bool) -> list[Finding]:
    """有名ブランドを騙る差出人・公式に酷似したドメインを検出する。

    ・表示名でブランドを名乗る × 送信ドメインが非公式
        → 認証なしなら「高」、認証済みなら「注意」(未登録の正規ドメイン誤検知を避ける)
    ・送信ドメインがホモグリフ等で公式ドメインに酷似 → 認証に関わらず「高」
    照合対象は差出人の表示名・ドメインのみ(件名/本文の言及では判定しない)。
    """
    from_domain = _domain_of(from_addr)
    if not from_domain:
        return []

    display_hay = (from_display or "").lower()
    domain_norm = from_domain.translate(_HOMOGLYPH_MAP).replace("rn", "m").replace("vv", "w")

    soft_note = (
        "送信ドメインは認証を通過していますが、当ツールが把握している正規ドメイン"
        "一覧には含まれていません。正規の別ドメインの可能性もあるため、公式アプリや"
        "ブックマークからの確認をおすすめします。"
        if strong_auth
        else "実在サービスを騙るフィッシングの典型パターンです。"
    )

    for pattern, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        if any(_same_org_domain(from_domain, official) for official in official_domains):
            continue
        brand_label = pattern.split("|")[0]
        ascii_tokens = [t for t in pattern.split("|") if t.isascii() and len(t) >= 4]

        # 1) ドメインが数字・記号でブランドに似せている(ホモグリフ)→ 常に危険
        for token in ascii_tokens:
            if not _domain_has_token(from_domain, token) and _domain_has_token(domain_norm, token):
                return [
                    Finding(
                        "high",
                        f"公式ドメインに酷似した差出人ドメイン: {from_domain}",
                        f"ドメイン「{from_domain}」は数字や記号で「{token}」に似せた"
                        "文字列を含みますが、正規ドメインではありません。"
                        "タイポスクワッティング(そっくりドメイン)によるなりすましの疑いがあります。",
                    )
                ]

        # 2) ドメインが正規ブランド名をそのまま含む(非公式)→ 認証で重み調整
        for token in ascii_tokens:
            if _domain_has_token(from_domain, token):
                return [
                    Finding(
                        "medium" if strong_auth else "high",
                        f"差出人ドメインが正規ブランド名を含みます: {from_domain}",
                        f"ドメイン「{from_domain}」は「{token}」を含みますが、正規ドメイン"
                        f"({', '.join(official_domains[:3])} など)ではありません。{soft_note}",
                    )
                ]

        # 3) 表示名でブランドを名乗る × 非公式ドメイン → 認証で重み調整
        if _brand_mentioned(pattern, display_hay):
            return [
                Finding(
                    "medium" if strong_auth else "high",
                    f"ブランド名を騙っている可能性: {brand_label}",
                    f"差出人が「{brand_label}」系の名称を名乗っていますが、実際の"
                    f"送信ドメインは「{from_domain}」で、正規ドメイン"
                    f"({', '.join(official_domains[:3])} など)ではありません。{soft_note}",
                )
            ]
    return []


def _domain_has_token(domain: str, token: str) -> bool:
    """ドメイン中にブランド語が語境界付きで含まれるか(pineapple の apple 等を除外)。"""
    return re.search(rf"(?:^|[^a-z0-9]){re.escape(token)}(?:[^a-z0-9]|$)", domain) is not None


def _brand_mentioned(pattern: str, haystack: str) -> bool:
    for token in pattern.split("|"):
        if token.isascii():
            if re.search(rf"\b{re.escape(token)}\b", haystack):
                return True
        elif token in haystack:
            return True
    return False


def _domain_of(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().strip(">").lower()


def _same_org_domain(domain_a: str, domain_b: str) -> bool:
    if not domain_a or not domain_b:
        return False
    if domain_a == domain_b:
        return True
    return domain_a.endswith("." + domain_b) or domain_b.endswith("." + domain_a)


# --- 配送経路 (Received) ----------------------------------------------


def _parse_received_chain(decoded: DecodedMail) -> list[ReceivedHop]:
    hops: list[ReceivedHop] = []
    for position, value in enumerate(decoded.all_headers("Received"), start=1):
        raw = " ".join(value.split())
        head, date = raw, None
        if ";" in raw:
            head, _, tail = raw.rpartition(";")
            date = tail.strip() or None

        from_host = from_comment = None
        from_match = re.search(r"\bfrom\s+(\[?[\w.\-:]+\]?)(?:\s*\(([^)]*)\))?", head, re.IGNORECASE)
        if from_match:
            from_host = from_match.group(1).strip("[]")
            from_comment = from_match.group(2)

        by_match = re.search(r"\bby\s+([\w.\-:]+)", head, re.IGNORECASE)
        by_host = by_match.group(1) if by_match else None

        from_segment = head
        if from_match and by_match and by_match.start() > from_match.start():
            from_segment = head[from_match.start():by_match.start()]
        ip, is_private = _pick_ip(from_segment)

        geo = None
        if ip:
            geo = describe_ip(ip, _reverse_hostname(from_host, from_comment))

        hops.append(
            ReceivedHop(
                position=position,
                from_host=from_host,
                from_comment=from_comment,
                ip=ip,
                ip_is_private=is_private,
                by_host=by_host,
                date=date,
                raw=raw,
                geo=geo,
            )
        )
    return hops


def _reverse_hostname(from_host: str | None, from_comment: str | None) -> str | None:
    """ジオ推定に使う逆引きホスト名を選ぶ(IP リテラルは除外)。"""
    for candidate in (from_host, from_comment):
        if not candidate:
            continue
        match = re.search(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,})\b", candidate.lower())
        if match and not IPV4_RE.fullmatch(match.group(1)):
            return match.group(1)
    return None


_LAN_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
)
_IPV6_LAN_NETWORKS = tuple(
    ipaddress.ip_network(net) for net in ("fc00::/7", "fe80::/10", "::1/128")
)


def _pick_ip(text: str) -> tuple[str | None, bool | None]:
    candidates: list[tuple[str, bool]] = []
    for raw_ip in IPV4_RE.findall(text):
        try:
            parsed = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        candidates.append((raw_ip, any(parsed in net for net in _LAN_NETWORKS)))
    for raw_ip in IPV6_BRACKET_RE.findall(text):
        normalized_ip = raw_ip.split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(normalized_ip)
        except ValueError:
            continue
        if parsed.version != 6:
            continue
        candidates.append(
            (normalized_ip, any(parsed in net for net in _IPV6_LAN_NETWORKS))
        )
    for ip, is_private in candidates:
        if not is_private:
            return ip, False
    if candidates:
        return candidates[0][0], True
    return None, None


def _guess_origin(hops: list[ReceivedHop]) -> OriginGuess | None:
    for hop in reversed(hops):
        if hop.ip and hop.ip_is_private is False:
            return OriginGuess(host=hop.from_host, ip=hop.ip, date=hop.date, hop_position=hop.position)
    for hop in reversed(hops):
        if hop.from_host or hop.ip:
            return OriginGuess(host=hop.from_host, ip=hop.ip, date=hop.date, hop_position=hop.position)
    return None


def _route_findings(hops: list[ReceivedHop], origin: OriginGuess | None) -> list[Finding]:
    findings: list[Finding] = []
    if not hops:
        findings.append(
            Finding(
                "info",
                "Received ヘッダーが見つかりません",
                "配送経路を推定できません。ヘッダー全体をコピーできているか確認してください。",
            )
        )
        return findings

    if origin:
        host = origin.host or "(ホスト名不明)"
        ip = f" [{origin.ip}]" if origin.ip else ""
        date = f" / {origin.date}" if origin.date else ""
        findings.append(
            Finding(
                "info",
                f"推定送信元: {host}{ip}",
                f"配送経路 {len(hops)} ホップ中、送信元に最も近い記録から推定{date}。"
                "※末尾側の Received は送信者が偽造できる点に注意してください。",
            )
        )

    private_origin = hops[-1]
    if private_origin.ip and private_origin.ip_is_private:
        findings.append(
            Finding(
                "info",
                "最初のホップはプライベート IP から投函されています",
                f"送信者の LAN 内 ({private_origin.ip}) から送信サーバーに渡された記録です。",
            )
        )

    findings.extend(_hop_time_findings(hops))
    return findings


def _hop_time_findings(hops: list[ReceivedHop]) -> list[Finding]:
    timeline = []
    for hop in hops:
        if not hop.date:
            continue
        try:
            timeline.append((hop.position, parsedate_to_datetime(hop.date)))
        except (TypeError, ValueError):
            continue

    for (pos_newer, time_newer), (_, time_older) in zip(timeline, timeline[1:]):
        if (time_newer.tzinfo is None) != (time_older.tzinfo is None):
            return [
                Finding(
                    "low",
                    "配送時刻のタイムゾーン情報が不完全です",
                    f"ホップ {pos_newer} 付近でタイムゾーン付き・なしの日時が混在しています。"
                    "時刻の前後関係を安全に比較できないため、配送時刻の整合性判定を省略しました。",
                )
            ]
        if (time_older - time_newer).total_seconds() > 300:
            return [
                Finding(
                    "low",
                    "配送時刻の並びに矛盾があります",
                    f"ホップ {pos_newer} 付近で受信時刻が逆行しています。サーバーの時計ずれの"
                    "こともありますが、偽造された Received ヘッダーの兆候である場合もあります。",
                )
            ]
    return []


def _date_consistency_findings(decoded: DecodedMail, hops: list[ReceivedHop]) -> list[Finding]:
    date_header = decoded.first_header("Date")
    if not date_header or not hops or not hops[0].date:
        return []
    try:
        claimed = parsedate_to_datetime(date_header)
        received = parsedate_to_datetime(hops[0].date)
    except (TypeError, ValueError):
        return []
    if claimed.tzinfo is None or received.tzinfo is None:
        return []

    diff_hours = abs((received - claimed).total_seconds()) / 3600
    if diff_hours > 72:
        return [
            Finding(
                "low",
                "Date ヘッダーと実際の受信時刻が大きく乖離しています",
                f"送信者が名乗る送信日時と受信サーバーの記録が約 {diff_hours:.0f} 時間"
                "ずれています。日時を偽装したメールの可能性があります。",
            )
        ]
    return []


# --- URL 検査 ----------------------------------------------------------


def _extract_urls(decoded: DecodedMail) -> list[UrlInfo]:
    seen: dict[str, UrlInfo] = {}
    for source in (decoded.body_text, decoded.body_html):
        for raw_url in URL_RE.findall(source or ""):
            url = raw_url.rstrip(".,;:!?、。」』")
            if url in seen:
                continue
            info = _inspect_url(url)
            if info:
                seen[url] = info
    return list(seen.values())


def _inspect_url(url: str) -> UrlInfo | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return UrlInfo(url=url, host="(解析不能)", flags=["URL を解析できません"], high_risk=True)
    host = parts.hostname or ""
    if not host:
        return UrlInfo(
            url=url,
            host="(ホストなし)",
            flags=["ホスト名がない不正な URL"],
            high_risk=True,
        )

    host_l = host.lower().rstrip(".")
    flags: list[str] = []
    high_risk = False
    try:
        ascii_host = host_l.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host_l
        flags.append("国際化ドメイン名を正規化できません")
        high_risk = True
    if not host_l.isascii() or "xn--" in ascii_host:
        flags.append("国際化ドメイン(IDN/Punycode、偽装ドメインの可能性)")
        high_risk = True
    try:
        ipaddress.ip_address(host_l)
    except ValueError:
        pass
    else:
        flags.append("IP アドレス直接指定")
        high_risk = True
    if parts.username is not None:
        flags.append("URL 内にユーザー情報 (@) を含む偽装形式")
        high_risk = True
    lookalike = _lookalike_brand(host_l)
    if lookalike:
        flags.append(f"正規ドメインを装った可能性 ({lookalike})")
        high_risk = True

    tld = host_l.rsplit(".", 1)[-1] if "." in host_l else ""
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"悪用されやすい TLD (.{tld})")
    if _is_shortener(host_l):
        flags.append("短縮 URL(実際のリンク先が隠されている)")
    if any(host_l == s or host_l.endswith("." + s) for s in DYNAMIC_DNS_SUFFIXES):
        flags.append("ダイナミック DNS(使い捨てホスト)")
    elif any(host_l == s or host_l.endswith("." + s) for s in FREE_HOSTING_SUFFIXES):
        flags.append("無料/一時ホスティング上のページ(誰でも作成可)")
    try:
        port = parts.port
    except ValueError:
        port = None
        flags.append("不正なポート指定(URL を安全に解析できません)")
        high_risk = True
    if port not in (None, 80, 443):
        flags.append(f"非標準ポート ({port})")

    return UrlInfo(url=url, host=host, flags=flags, high_risk=high_risk)


def _is_shortener(host: str) -> bool:
    if host in URL_SHORTENERS:
        return True
    # 既知リストに無くても「短いドメイン + ドメイン名がほぼ無い」形は短縮系が多い
    labels = host.split(".")
    if len(labels) == 2 and len(labels[0]) <= 4 and len(labels[1]) <= 3:
        return True
    return False


def _lookalike_brand(host: str) -> str | None:
    normalized = host.lower().translate(_HOMOGLYPH_MAP).replace("rn", "m").replace("vv", "w")
    for pattern, official_domains in BRAND_OFFICIAL_DOMAINS.items():
        ascii_tokens = [t for t in pattern.split("|") if t.isascii() and len(t) >= 4]
        for token in ascii_tokens:
            if token in normalized and not any(
                _same_org_domain(host.lower(), official) for official in official_domains
            ):
                return token
    return None


def _url_findings(urls: list[UrlInfo]) -> list[Finding]:
    findings: list[Finding] = []
    flagged = [u for u in urls if u.flags]
    for url_info in flagged:
        severity = "high" if url_info.high_risk else "medium"
        findings.append(
            Finding(
                severity,
                f"不審な URL: {defang_url(url_info.url)}",
                " / ".join(url_info.flags),
            )
        )
    if urls and not flagged:
        findings.append(Finding("ok", f"本文中の URL ({len(urls)} 件) に既知の危険パターンはありません"))
    return findings


def _anchor_mismatch_findings(decoded: DecodedMail) -> list[Finding]:
    if not decoded.body_html:
        return []
    findings: list[Finding] = []
    for href, anchor_text in ANCHOR_RE.findall(decoded.body_html):
        text_urls = URL_RE.findall(anchor_text)
        if text_urls:
            shown_label = text_urls[0]
            shown_url = shown_label
        else:
            bare_match = BARE_DOMAIN_RE.search(anchor_text)
            if not bare_match:
                continue
            shown_label = bare_match.group(1)
            shown_url = "https://" + shown_label
        if not shown_url:
            continue
        try:
            href_host = (urlsplit(href).hostname or "").lower()
            shown_host = (urlsplit(shown_url).hostname or "").lower()
        except ValueError:
            findings.append(
                Finding(
                    "high",
                    "リンク先 URL を安全に解析できません",
                    f"HTML リンクのリンク先「{defang_url(href)}」が不正な形式です。"
                    "解析を妨げる細工の可能性があるため、リンクを開かないでください。",
                )
            )
            continue
        if href_host and shown_host and not _same_org_domain(href_host, shown_host):
            findings.append(
                Finding(
                    "high",
                    "表示上の URL と実際のリンク先が異なります",
                    f"本文には「{defang_text(shown_label)}」と表示されていますが、実際の"
                    f"リンク先は「{defang_url(href)}」です。フィッシングの典型的な手口です。",
                )
            )
    return findings


def _html_threat_findings(decoded: DecodedMail) -> list[Finding]:
    """HTML 本文に含まれる能動的な攻撃要素を検出する。"""
    html_body = decoded.body_html
    if not html_body:
        return []
    normalized_html = html.unescape(html_body)

    findings: list[Finding] = []
    if (
        SCRIPT_RE.search(normalized_html)
        or JS_URI_RE.search(normalized_html)
        or EVENT_HANDLER_RE.search(normalized_html)
    ):
        findings.append(
            Finding(
                "high",
                "本文にスクリプト(JavaScript)が埋め込まれています",
                "メール本文内のスクリプトは通常のメールではまず使われず、"
                "多くのメールソフトも実行を禁止しています。悪意のある挙動の可能性が高いです。",
            )
        )
    if EXTERNAL_FORM_RE.search(normalized_html):
        findings.append(
            Finding(
                "high",
                "本文に外部へ送信する入力フォームがあります",
                "メール内のフォームは、ID・パスワード・カード番号などを直接盗み取る"
                "フィッシングの手口に使われます。絶対に入力しないでください。",
            )
        )
    if META_REFRESH_RE.search(normalized_html):
        findings.append(
            Finding(
                "medium",
                "本文に自動リダイレクト (meta refresh) が含まれています",
                "開いた瞬間に別のサイトへ自動転送しようとしています。",
            )
        )
    if IFRAME_RE.search(normalized_html):
        findings.append(
            Finding(
                "medium",
                "本文に外部コンテンツの埋め込み (iframe) があります",
                "別サイトの内容を本文に読み込ませる要素です。悪用されることがあります。",
            )
        )
    return findings


# --- キーワード・本文形式・添付ファイル・スパム判定 ----------------------


def _keyword_findings(decoded: DecodedMail) -> list[Finding]:
    subject = decoded.first_header("Subject") or ""
    haystack = (subject + "\n" + decoded.body_text).lower()
    matched = sorted({kw for kw in URGENCY_KEYWORDS if kw.lower() in haystack})
    if len(matched) < 2:
        return []
    severity = "medium" if len(matched) >= 4 else "low"
    return [
        Finding(
            severity,
            "受信者を焦らせる・誘導する表現が含まれています",
            "検出した表現: " + "、".join(f"「{kw}」" for kw in matched[:8])
            + ("(他にもあり)" if len(matched) > 8 else "")
            + "。緊急性や不安を演出して判断力を奪うのはフィッシングの常套手段ですが、"
            "正規の通知メールでも使われる表現です。他の兆候と併せて判断してください。",
        )
    ]


def _content_spam_findings(decoded: DecodedMail, urls: list[UrlInfo]) -> list[Finding]:
    """本文の内容から迷惑メール(スパム)らしさを独自に評価する。

    X-Spam ヘッダーに依存せず、貼り付けられた本文だけで判断する。
    """
    subject = decoded.first_header("Subject") or ""
    body = decoded.body_text or ""
    haystack = (subject + "\n" + body)
    lowered = haystack.lower()

    signals: list[str] = []

    matched_kw = sorted({kw for kw in SPAM_KEYWORDS if kw.lower() in lowered})
    if matched_kw:
        signals.append("勧誘・射幸的な語句: " + "、".join(matched_kw[:6]) + ("…" if len(matched_kw) > 6 else ""))

    # 過剰な感嘆符・記号
    if len(re.findall(r"[!!]", haystack)) >= 4:
        signals.append("感嘆符の多用")
    # 全角/半角の伏せ字・記号連続(例: 儲 か る、★彡)
    if len(re.findall(r"[★☆◆■※→▼【】]", haystack)) >= 6:
        signals.append("装飾記号の多用")
    # 金額表記
    if re.search(r"[0-9０-９]{1,3}[,，]?[0-9０-９]{3}\s*円|[0-9０-９]+\s*万円|[$¥][0-9,]{4,}", haystack):
        signals.append("高額の金額表示")
    # 大量のリンク
    if len(urls) >= 6:
        signals.append(f"本文中のリンクが多い({len(urls)} 件)")
    # 画像のみ(HTML はあるが表示テキストがほとんど無い)
    if decoded.body_html and len(body.strip()) < 20 and "<img" in decoded.body_html.lower():
        signals.append("本文が画像だけ(テキストなし)")
    # 英語の全大文字の叫び
    caps = re.findall(r"\b[A-Z]{4,}\b", haystack)
    if len(caps) >= 3:
        signals.append("英大文字の多用")

    if len(signals) < 2:
        return []
    severity = "high" if len(signals) >= 4 else "medium"
    return [
        Finding(
            severity,
            "迷惑メール(スパム)特有の特徴が複数あります",
            "検出: " + " / ".join(signals)
            + "。宣伝・詐欺目的のばらまきメールに典型的なパターンです。",
        )
    ]


def _body_format_findings(decoded: DecodedMail) -> list[Finding]:
    if decoded.body_content_type == "text/html":
        return [
            Finding(
                "info",
                "本文が HTML のみで構成されています",
                "テキスト版を持たない HTML のみのメールです。迷惑メールで多く"
                "見られますが、正規の広告・通知メールでも一般的な形式です。",
            )
        ]
    return []


def _attachment_findings(decoded: DecodedMail) -> list[Finding]:
    findings: list[Finding] = []
    for attachment in decoded.attachments:
        name = attachment.filename
        normalized_name = name.rstrip(" .")
        parts = normalized_name.lower().rsplit(".", 2)
        ext = parts[-1] if len(parts) >= 2 else ""

        # 二重拡張子(invoice.pdf.exe など)
        if len(parts) >= 3 and parts[-2] in DOCUMENT_LOOKALIKE_EXTS and ext in DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    "high",
                    f"二重拡張子の偽装ファイル: {name}",
                    "文書ファイルに見せかけた実行ファイルです。極めて危険なので開かないでください。",
                )
            )
            continue

        if ext in DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    "high",
                    f"実行可能な添付ファイル: {name}",
                    "実行するとマルウェアに感染するおそれのある形式です。絶対に開かないでください。",
                )
            )
        elif ext in MACRO_EXTENSIONS:
            findings.append(
                Finding(
                    "high",
                    f"マクロ付き Office 文書: {name}",
                    "マクロを有効化させてマルウェアを実行させる代表的な攻撃手口です。開かないでください。",
                )
            )
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append(
                Finding(
                    "low",
                    f"圧縮ファイルの添付: {name}",
                    "ウイルススキャンから中身を隠すために圧縮ファイル(特にパスワード付き)が"
                    "使われることがあります。心当たりがなければ開かないでください。",
                )
            )
    return findings


def _spam_findings(spam: SpamSummary) -> list[Finding]:
    if not spam.available:
        return []
    if spam.verdict == "Spam":
        detail = ""
        if spam.score is not None and spam.required_score is not None:
            detail = f"スパムスコア {spam.score:g}(しきい値 {spam.required_score:g})。"
        if spam.tests:
            detail += " 検出ルール: " + ", ".join(spam.tests[:6])
        return [Finding("high", "メールサーバーのスパムフィルタがスパムと判定しています", detail)]
    if (
        spam.score is not None
        and spam.required_score is not None
        and spam.required_score > 0
        and spam.score >= spam.required_score * 0.7
    ):
        return [
            Finding(
                "medium",
                "スパムスコアがしきい値に接近しています",
                f"スコア {spam.score:g} / しきい値 {spam.required_score:g}。判定はすり抜けて"
                "いますが、スパムフィルタも複数の不審な特徴を検出しています。",
            )
        ]
    if spam.verdict == "Not Spam":
        return [Finding("ok", "メールサーバーのスパムフィルタは通過しています")]
    return []


# --- 無害化 (defang) ----------------------------------------------------


def defang_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)

    scheme = re.sub(r"^http", "hxxp", parts.scheme, flags=re.IGNORECASE)
    netloc = parts.netloc
    if host:
        matches = list(re.finditer(re.escape(host), netloc, flags=re.IGNORECASE))
        if matches:
            match = matches[-1]
            defanged_host = match.group(0).replace(".", "[.]")
            netloc = netloc[:match.start()] + defanged_host + netloc[match.end():]
    return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))


def defang_text(text: str) -> str:
    parts: list[str] = []
    previous_end = 0
    for match in URL_RE.finditer(text):
        before = text[previous_end:match.start()]
        parts.append(
            BARE_DOMAIN_RE.sub(
                lambda bare: bare.group(0).replace(".", "[.]"),
                before,
            )
        )
        parts.append(defang_url(match.group(0)))
        previous_end = match.end()
    parts.append(
        BARE_DOMAIN_RE.sub(
            lambda bare: bare.group(0).replace(".", "[.]"),
            text[previous_end:],
        )
    )
    return "".join(parts)
