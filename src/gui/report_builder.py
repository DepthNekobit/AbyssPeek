"""解析結果・デコード結果を QTextBrowser 用の HTML に整形する。"""

import html

from src.gui.theme import severity_colors
from src.services.output_formatter import decoded_sections
from src.services.security_analyzer import (
    SEVERITY_LABEL,
    SEVERITY_SCORE,
    SecurityReport,
    defang_url,
)
from src.services.spam_analyzer import SpamSummary
from src.usecases.analyze_mail import AnalysisResult


def report_css(p: dict) -> str:
    return f"""
    body {{ color: {p["text"]}; background-color: {p["surface2"]}; }}
    h2 {{ font-size: 15px; color: {p["accent"]}; margin-top: 18px; margin-bottom: 6px; }}
    p, li {{ font-size: 13px; }}
    .muted {{ color: {p["muted"]}; font-size: 12px; }}
    table {{ font-size: 13px; }}
    td {{ padding: 4px 10px; }}
    """


def build_decoded_html(result: AnalysisResult, palette: dict) -> str:
    """デコード結果をセクションごとのカードで表示する HTML を組み立てる。

    ウィンドウ幅に依存する文字罫線を使わないため、リサイズしても
    区切りが崩れない。
    """
    parts: list[str] = []
    for title, content in decoded_sections(result.decoded, result.defang_urls):
        body = html.escape(content.rstrip()).replace("\n", "<br/>")
        parts.append(
            f'<table width="100%" cellspacing="0" cellpadding="8">'
            f'<tr><td bgcolor="{palette["surface3"]}">'
            f'<span style="color:{palette["accent"]}; font-weight:bold;">■ {html.escape(title)}</span>'
            f"</td></tr>"
            f'<tr><td bgcolor="{palette["surface"]}">{body}</td></tr>'
            f"</table><p></p>"
        )
    return "\n".join(parts)


def decoded_placeholder_html(palette: dict) -> str:
    return (
        f'<p style="color:{palette["muted"]};">「変換」を押すと、ここに '
        f"<b>送信元 / 送信先 / 件名 / 日時 / 本文</b> に整理された結果が表示されます。</p>"
    )


def build_report_html(result: AnalysisResult, palette: dict) -> str:
    report = result.security
    colors = severity_colors(palette)
    parts: list[str] = []

    parts.append(_risk_banner(report, palette))
    parts.append("<h2>◆ 判定の要点(スコア内訳)</h2>")
    parts.append(_findings_list(report, colors, palette))
    parts.append("<h2>◆ 送信ドメイン認証 (SPF / DKIM / DMARC)</h2>")
    parts.append(_auth_table(report, palette))
    parts.append("<h2>◆ 配送経路 (Received ヘッダー)</h2>")
    parts.append(_route_section(report, palette))
    parts.append("<h2>◆ 本文中の URL</h2>")
    parts.append(_url_section(report, palette, result.defang_urls))
    parts.append("<h2>◆ スパムフィルタの判定</h2>")
    parts.append(_spam_section(result.spam, palette))
    parts.append(
        f'<p class="muted">※ 総合評価は上記「判定の要点」各項目の加点合計です。'
        f"なりすまし確定級の強い兆候(DMARC 失敗・リンク先すり替え・ブランド偽装・"
        f"マルウェア添付など)は単独で「高」、弱い兆候は蓄積して「中」に達します。<br/>"
        f"※ 本解析は貼り付けられたテキストのみをローカルで処理し、外部通信は行いません"
        f"(地域推定も内蔵データによるオフライン処理)。Received の末尾側や地域推定は"
        f"あくまで参考情報です。</p>"
    )
    return "\n".join(parts)


def _risk_banner(report: SecurityReport, p: dict) -> str:
    level = report.risk_level
    if level == "高":
        fg, bg = p["danger"], p["danger_bg"]
        label = "リスク評価: 高(危険)"
        note = "重大な危険の兆候、または複数の不審な特徴が見つかりました。リンクや添付ファイルを開かないでください。"
    elif level == "中":
        fg, bg = p["warn"], p["warn_bg"]
        label = "リスク評価: 中(注意)"
        note = "不審な特徴があります。差出人に心当たりがない場合は開かず削除を検討してください。"
    elif level == "低":
        fg, bg = p["info"], p["info_bg"]
        label = "リスク評価: 低"
        note = "大きな問題は見つかりませんでしたが、軽微な注意点があります。"
    else:
        fg, bg = p["ok"], p["ok_bg"]
        label = "リスク評価: 問題なし"
        note = "既知の危険パターンは検出されませんでした。"
    return (
        f'<table width="100%" cellspacing="0" cellpadding="10" bgcolor="{bg}">'
        f'<tr><td><span style="color:{fg}; font-size:16px; font-weight:bold;">'
        f"&#9888; {label}&nbsp;&nbsp;<small>スコア {report.risk_score} / 100</small></span><br/>"
        f'<span style="color:{p["text"]}; font-size:12px;">{note}</span></td></tr></table>'
    )


def _findings_list(report: SecurityReport, colors: dict, p: dict) -> str:
    rows: list[str] = []
    for finding in report.findings:
        fg, bg = colors.get(finding.severity, colors["info"])
        badge = SEVERITY_LABEL.get(finding.severity, finding.severity)
        points = SEVERITY_SCORE.get(finding.severity, 0)
        score_line = (
            f'<span style="color:{fg}; font-weight:bold;">+{points}点</span>'
            if points > 0
            else f'<span style="color:{p["muted"]}; font-size:11px;">±0点</span>'
        )
        detail = (
            f'<br/><span style="font-size:12px;">{html.escape(finding.detail)}</span>'
            if finding.detail
            else ""
        )
        rows.append(
            f'<tr><td width="62" bgcolor="{bg}" align="center">'
            f'<span style="color:{fg}; font-weight:bold; font-size:11px;">{badge}</span><br/>'
            f'{score_line}</td>'
            f'<td><b>{html.escape(finding.title)}</b>{detail}</td></tr>'
        )
    if not rows:
        return "<p>特記事項はありません。</p>"
    # 加点の内訳サマリ
    counts: dict[str, int] = {}
    for finding in report.findings:
        if SEVERITY_SCORE.get(finding.severity, 0) > 0:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
    breakdown = "、".join(
        f"{SEVERITY_LABEL[s]} {counts[s]}件×{SEVERITY_SCORE[s]}点"
        for s in ("high", "medium", "low")
        if counts.get(s)
    )
    summary = (
        f'<p class="muted">加点内訳: {breakdown} = 合計 {report.risk_score} 点'
        f"(上限 100)。しきい値: 高 40 / 中 18 / 低 7 点。</p>"
        if breakdown
        else '<p class="muted">加点項目はありません(合計 0 点)。</p>'
    )
    table = f'<table width="100%" cellspacing="4" cellpadding="5">{"".join(rows)}</table>'
    return table + summary


def _auth_table(report: SecurityReport, p: dict) -> str:
    auth = report.auth
    if auth.spf is None and auth.dkim is None and auth.dmarc is None:
        if auth.ignored_sources:
            sources = html.escape(", ".join(auth.ignored_sources))
            return (
                '<p class="muted">信頼できる認証結果は見つかりませんでした。'
                f"受信サーバーと一致しない発行元 ({sources}) の Authentication-Results は、"
                "偽造可能なため判定から除外しました。</p>"
            )
        return '<p class="muted">認証結果ヘッダー (Authentication-Results) が見つかりませんでした。</p>'

    def cell(result: str | None, extra: str = "") -> str:
        shown = result or "記録なし"
        if result == "pass":
            color = p["ok"]
        elif result in ("fail", "softfail"):
            color = p["danger"]
        elif result is None:
            color = p["muted"]
        else:
            color = p["warn"]
        return f'<span style="color:{color}; font-weight:bold;">{html.escape(shown)}</span>{extra}'

    dkim_extra = f' <span class="muted">(d={html.escape(auth.dkim_domain)})</span>' if auth.dkim_domain else ""
    dmarc_extra = f' <span class="muted">(p={html.escape(auth.dmarc_policy)})</span>' if auth.dmarc_policy else ""
    source = (
        f'<p class="muted">判定サーバー: {html.escape(auth.source)}</p>' if auth.source else ""
    )
    return (
        f'<table cellspacing="0" cellpadding="6" width="100%" bgcolor="{p["surface3"]}">'
        f"<tr>"
        f"<td><b>SPF</b><br/>{cell(auth.spf)}</td>"
        f"<td><b>DKIM</b><br/>{cell(auth.dkim, dkim_extra)}</td>"
        f"<td><b>DMARC</b><br/>{cell(auth.dmarc, dmarc_extra)}</td>"
        f"</tr></table>{source}"
    )


def _route_section(report: SecurityReport, p: dict) -> str:
    if not report.hops:
        return '<p class="muted">Received ヘッダーが見つかりませんでした。</p>'

    parts: list[str] = []
    origin_hop = next((h for h in report.hops if h.position == report.origin.hop_position), None) if report.origin else None
    if report.origin:
        host = html.escape(report.origin.host or "(ホスト名不明)")
        ip = f" [{html.escape(report.origin.ip)}]" if report.origin.ip else ""
        date = html.escape(report.origin.date or "日時不明")
        geo_txt = ""
        if origin_hop and origin_hop.geo:
            geo_txt = f' <span style="color:{p["accent"]};">/ {html.escape(origin_hop.geo.label)}</span>'
        parts.append(
            f'<p><b>推定送信元:</b> <span style="color:{p["accent"]}; font-weight:bold;">'
            f"{host}{ip}</span>{geo_txt} <span class=\"muted\">({date})</span></p>"
        )

    # 通過地域の一覧(送信元 → 受信側の順)
    regions: list[str] = []
    for hop in reversed(report.hops):
        if hop.geo and not hop.geo.is_private and hop.geo.label not in ("地域を特定できません",):
            label = hop.geo.label
            if label not in regions:
                regions.append(label)
    if regions:
        parts.append(
            f'<p><b>通過した地域:</b> {" → ".join(html.escape(r) for r in regions)}</p>'
        )

    header_bg = p["surface3"]
    rows = [
        f'<tr bgcolor="{header_bg}">'
        f"<td><b>#</b></td><td><b>from(送信側)</b></td><td><b>IP</b></td>"
        f"<td><b>推定地域</b></td><td><b>日時</b></td></tr>"
    ]
    for hop in report.hops:
        ip_text = hop.ip or "-"
        geo_label = "-"
        if hop.geo:
            geo_label = hop.geo.label
        elif hop.ip and hop.ip_is_private:
            geo_label = "内部ネットワーク (LAN)"
        rows.append(
            "<tr>"
            f"<td>{hop.position}</td>"
            f"<td>{html.escape(hop.from_host or '-')}</td>"
            f"<td>{html.escape(ip_text)}</td>"
            f"<td>{html.escape(geo_label)}</td>"
            f"<td>{html.escape(hop.date or '-')}</td>"
            "</tr>"
        )
    parts.append(
        f'<table width="100%" cellspacing="0" cellpadding="5" border="0">{"".join(rows)}</table>'
    )
    parts.append(
        '<p class="muted">#1 が受信サーバーに最も近い記録です。番号が大きいほど送信元に近くなります。'
        "地域は IP アドレスの割当ブロックと逆引きホスト名からのオフライン推定で、概略です。</p>"
    )
    return "\n".join(parts)


def _url_section(report: SecurityReport, p: dict, defang_urls: bool) -> str:
    if not report.urls:
        return '<p class="muted">本文から URL は検出されませんでした。</p>'

    url_label = "URL(無害化表示)" if defang_urls else "URL"
    rows = [f'<tr bgcolor="{p["surface3"]}"><td><b>{url_label}</b></td><td><b>注意点</b></td></tr>']
    for url_info in report.urls:
        if url_info.flags:
            flags = f'<span style="color:{p["danger"]};">{html.escape(" / ".join(url_info.flags))}</span>'
        else:
            flags = f'<span style="color:{p["ok"]};">既知の危険パターンなし</span>'
        shown_url = defang_url(url_info.url) if defang_urls else url_info.url
        rows.append(f"<tr><td>{html.escape(shown_url)}</td><td>{flags}</td></tr>")
    note = (
        '<p class="muted">URL は安全のため hxxp / [.] 形式に無害化して表示しています。'
        "そのままブラウザに貼り付けても開けません。</p>"
        if defang_urls
        else '<p class="muted">URL の無害化表示はオフです。コピー後の誤クリックに注意してください。</p>'
    )
    return f'<table width="100%" cellspacing="0" cellpadding="5">{"".join(rows)}</table>' + note


def _spam_section(spam: SpamSummary, p: dict) -> str:
    if not spam.available:
        return '<p class="muted">スパム判定ヘッダー (X-Spam-Status など) が見つかりませんでした。</p>'

    if spam.verdict == "Spam":
        verdict_color = p["danger"]
    elif spam.verdict == "Not Spam":
        verdict_color = p["ok"]
    else:
        verdict_color = p["warn"]
    verdict_label = "スパム" if spam.verdict == "Spam" else ("非スパム" if spam.verdict == "Not Spam" else "不明")
    lines = [
        f'<p><b>判定:</b> <span style="color:{verdict_color}; font-weight:bold;">{verdict_label}</span>'
    ]
    if spam.score is not None:
        required = f" / しきい値 {spam.required_score:g}" if spam.required_score is not None else ""
        lines.append(f'&nbsp;&nbsp;<b>スコア:</b> {spam.score:g}{required}')
    lines.append("</p>")
    if spam.tests:
        lines.append(
            f'<p class="muted">検出ルール: {html.escape(", ".join(spam.tests))}</p>'
        )
    if spam.checker_version:
        lines.append(f'<p class="muted">エンジン: {html.escape(spam.checker_version)}</p>')
    return "\n".join(lines)
