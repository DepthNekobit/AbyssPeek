"""ヘルプダイアログに表示する HTML コンテンツ(テーマ対応)。"""


def help_css(p: dict) -> str:
    return f"""
    body {{ color: {p["text"]}; background-color: {p["surface2"]}; }}
    h1 {{ font-size: 19px; color: {p["accent"]}; margin-bottom: 4px; }}
    h2 {{ font-size: 15px; color: {p["accent"]}; margin-top: 20px; margin-bottom: 6px; }}
    h3 {{ font-size: 13px; color: {p["text"]}; margin-top: 14px; margin-bottom: 4px; }}
    p, li {{ font-size: 13px; line-height: 150%; }}
    .lead {{ color: {p["muted"]}; font-size: 13px; }}
    .muted {{ color: {p["muted"]}; font-size: 12px; }}
    .kbd {{ background-color: {p["surface3"]}; color: {p["accent"]}; font-family: monospace; }}
    td {{ padding: 5px 10px; font-size: 13px; }}
    """


def _card(p: dict, color_key: str, bg_key: str, title: str, body: str) -> str:
    return (
        f'<table width="100%" cellspacing="0" cellpadding="9" bgcolor="{p[bg_key]}">'
        f'<tr><td><b><span style="color:{p[color_key]};">{title}</span></b><br/>'
        f'<span style="font-size:12px;">{body}</span></td></tr></table>'
    )


def _steps_table(p: dict, steps: list[tuple[str, str]]) -> str:
    rows = []
    for number, (title, body) in enumerate(steps, start=1):
        rows.append(
            f'<tr><td width="40" align="center" bgcolor="{p["surface3"]}">'
            f'<span style="color:{p["accent"]}; font-size:16px; font-weight:bold;">{number}</span></td>'
            f"<td><b>{title}</b><br/>"
            f'<span style="font-size:12px;">{body}</span></td></tr>'
        )
    return f'<table width="100%" cellspacing="6" cellpadding="6">{"".join(rows)}</table>'


def build_help_pages(p: dict) -> list[tuple[str, str]]:
    """(ナビゲーション名, HTML) のリストを返す。"""
    return [
        ("🏠 はじめに", _page_intro(p)),
        ("🚀 基本的な使い方", _page_usage(p)),
        ("📄 デコード結果の見方", _page_decode(p)),
        ("🛡️ 解析レポートの見方", _page_report(p)),
        ("🔐 セキュリティ機能一覧", _page_security(p)),
        ("💡 ヒントと FAQ", _page_faq(p)),
    ]


def _page_intro(p: dict) -> str:
    return f"""
<h1>AbyssPeek へようこそ</h1>
<p class="lead">迷惑メールの深淵を、安全な場所から覗き込むためのツールです。</p>

<p><b>AbyssPeek</b> は、怪しいメールの「ヘッダー(メッセージのソース)」を貼り付けるだけで、
エンコードされた件名や本文を読める形にデコードし、フィッシング・なりすましの兆候を
自動で解析するデスクトップツールです。</p>

{_card(p, "ok", "ok_bg", "✔ 完全ローカル処理",
       "貼り付けた内容が外部に送信されることはありません。URL への接続や DNS 参照も行わないため、"
       "解析したことが攻撃者に知られる心配がありません。")}
<p></p>
{_card(p, "info", "info_bg", "ℹ 想定している使い方",
       "「届いたメールが本物か怪しい」と感じたとき、メール本体を開かずにヘッダーだけを"
       "コピーして貼り付け、リスクを判断する材料を得ることを想定しています。")}

<h2>主な機能</h2>
<ul>
  <li>MIME エンコードされた件名・差出人・本文のデコード(日本語文字コード対応)</li>
  <li>送信元 / 送信先 / 件名 / 本文 に区分した見やすい出力</li>
  <li>SPF / DKIM / DMARC 認証結果の読み取りと評価</li>
  <li>Received ヘッダーからの配送経路・推定送信元の解析</li>
  <li>本文 URL の危険パターン検査と無害化(defang)表示</li>
  <li>リスクスコアによる総合判定(問題なし / 低 / 中 / 高)</li>
  <li>解析結果のテキスト / HTML 保存</li>
</ul>
"""


def _page_usage(p: dict) -> str:
    return f"""
<h1>基本的な使い方</h1>
<p class="lead">3 ステップで解析できます。</p>

{_steps_table(p, [
    ("メールのヘッダー(ソース)をコピーする",
     "メールソフトで対象のメールを開き、「メッセージのソースを表示」「元のメッセージを表示」"
     "などのメニューから全文をコピーします。Gmail なら「︙ → メッセージのソースを表示」、"
     "Outlook なら「ファイル → プロパティ → インターネットヘッダー」です。"),
    ("左のテキストボックスに貼り付ける",
     "コピーした内容を <b>そのまま</b> 左側の入力欄に貼り付けます。ヘッダーだけでも、"
     "本文を含むソース全体でも解析できます。ファイルから読み込む場合は "
     "<span class='kbd'>&nbsp;Ctrl+O&nbsp;</span> でも開けます。"),
    ("中央の「変換」矢印ボタンを押す",
     "右側に「送信元 / 送信先 / 件名 / 本文」に整理されたデコード結果が表示されます。"
     "「解析レポート」タブに切り替えると、セキュリティ解析の詳細を確認できます。"
     "<span class='kbd'>&nbsp;Ctrl+Enter&nbsp;</span> でも実行できます。"),
])}

<h2>よく使うショートカット</h2>
<table width="100%" cellspacing="0" cellpadding="5">
  <tr bgcolor="{p["surface3"]}"><td><b>操作</b></td><td><b>キー</b></td></tr>
  <tr><td>変換を実行</td><td><span class="kbd">&nbsp;Ctrl+Enter&nbsp;</span> / <span class="kbd">&nbsp;F5&nbsp;</span></td></tr>
  <tr><td>ヘッダーファイルを開く</td><td><span class="kbd">&nbsp;Ctrl+O&nbsp;</span></td></tr>
  <tr><td>デコード結果を保存</td><td><span class="kbd">&nbsp;Ctrl+S&nbsp;</span></td></tr>
  <tr><td>入力をクリア</td><td><span class="kbd">&nbsp;Ctrl+L&nbsp;</span></td></tr>
  <tr><td>ライト / ダークモード切替</td><td><span class="kbd">&nbsp;Ctrl+D&nbsp;</span></td></tr>
  <tr><td>このヘルプ</td><td><span class="kbd">&nbsp;F1&nbsp;</span></td></tr>
</table>

<p class="muted">まず試してみたい場合は、メニューの「ヘルプ → サンプルヘッダーを読み込む」で
フィッシングメールを模したサンプルを読み込めます。</p>
"""


def _page_decode(p: dict) -> str:
    return f"""
<h1>デコード結果の見方</h1>
<p class="lead">右側の「デコード結果」タブには、メールが 5 つの区分に整理して表示されます。</p>

<table width="100%" cellspacing="6" cellpadding="7">
  <tr><td width="150" bgcolor="{p["surface3"]}"><b>■ 送信元 (From)</b></td>
      <td>表示名とメールアドレス。<b>表示名は自由に偽装できる</b>ため、
      &lt; &gt; 内の実際のアドレスとドメインを必ず確認してください。</td></tr>
  <tr><td bgcolor="{p["surface3"]}"><b>■ 送信先 (To / Cc)</b></td>
      <td>宛先。自分のアドレスが含まれない(BCC 一斉送信)場合、
      ばらまき型の迷惑メールの可能性が高まります。</td></tr>
  <tr><td bgcolor="{p["surface3"]}"><b>■ 件名 (Subject)</b></td>
      <td>MIME エンコード(=?UTF-8?B?... など)をデコードした読める形の件名です。</td></tr>
  <tr><td bgcolor="{p["surface3"]}"><b>■ 日時 (Date)</b></td>
      <td>送信者が名乗っている送信日時。極端に古い/未来の日時は不審な兆候です。</td></tr>
  <tr><td bgcolor="{p["surface3"]}"><b>■ 本文 (Body)</b></td>
      <td>Base64 等をデコードした本文。HTML メールはテキストに変換して表示します。</td></tr>
</table>

<h2>URL の無害化(defang)について</h2>
<p>本文中の URL は誤クリックを防ぐため、既定で次のように書き換えて表示します。</p>
{_card(p, "accent", "surface3", "無害化の例",
       "https://example.com/login &nbsp;→&nbsp; hxxps://example[.]com/login")}
<p class="muted">この形式はセキュリティ業界で広く使われている表記で、コピーしても
そのままではブラウザで開けません。「表示 → URL を無害化して表示」でオフにできますが、
危険なリンクを誤って開かないよう、オンのままにしておくことを推奨します。</p>
"""


def _page_report(p: dict) -> str:
    return f"""
<h1>解析レポートの見方</h1>
<p class="lead">「解析レポート」タブでは、ヘッダーから読み取れる危険の兆候を自動評価します。</p>

<h2>リスク評価(総合判定)</h2>
<table width="100%" cellspacing="4" cellpadding="6">
  <tr><td width="110" bgcolor="{p["danger_bg"]}" align="center">
        <span style="color:{p["danger"]}; font-weight:bold;">高(危険)</span></td>
      <td>重大な危険の兆候、または複数の不審な特徴を検出した状態。リンク・添付を開かず削除推奨。</td></tr>
  <tr><td bgcolor="{p["warn_bg"]}" align="center">
        <span style="color:{p["warn"]}; font-weight:bold;">中(注意)</span></td>
      <td>不審な特徴あり。心当たりのない差出人なら開かないでください。</td></tr>
  <tr><td bgcolor="{p["info_bg"]}" align="center">
        <span style="color:{p["info"]}; font-weight:bold;">低</span></td>
      <td>軽微な注意点のみ。念のため差出人と内容を確認してください。</td></tr>
  <tr><td bgcolor="{p["ok_bg"]}" align="center">
        <span style="color:{p["ok"]}; font-weight:bold;">問題なし</span></td>
      <td>既知の危険パターンは未検出。ただし「安全の保証」ではありません。</td></tr>
</table>

{_card(p, "info", "info_bg", "ℹ 総合評価の考え方(スコア内訳)",
       "各項目を重み付けして合計します。危険 +40 点 / 注意 +15 点 / 軽微 +5 点で、"
       "合計が 高 40 点・中 18 点・低 7 点のしきい値を超えると評価が上がります。"
       "「判定の要点」では各項目にどれだけ加点されたか(+○点)を明示するので、"
       "何が理由でその評価になったかを確認できます。なりすまし確定級の強い兆候"
       "(DMARC 失敗・リンク先すり替え・ブランド偽装・マルウェア添付など)は 1 件で「高」、"
       "弱い兆候は複数積み重なって「中」に達します。")}

<h2>送信ドメイン認証 (SPF / DKIM / DMARC)</h2>
<p>受信サーバーが記録した「差出人ドメインが本物か」の検証結果です。</p>
<ul>
  <li><b>SPF</b> — 送信サーバーの IP がドメインの正規サーバーとして登録されているか</li>
  <li><b>DKIM</b> — メールに付けられた電子署名が正しいか(改ざん検知)</li>
  <li><b>DMARC</b> — SPF / DKIM の結果と From 表示の整合性ポリシー検証</li>
</ul>
{_card(p, "danger", "danger_bg", "fail は要警戒",
       "特に SPF と DMARC の fail は、差出人アドレスが偽装されている強い兆候です。")}

<h2>配送経路 (Received ヘッダー)と通過地域</h2>
<p>メールが経由したサーバーの記録を新しい順(#1 が受信側)に一覧表示し、
送信元に最も近い記録から「推定送信元」を表示します。各ホップの IP アドレスから
<b>推定される地域(国・大陸)</b>と、逆引きホスト名から分かる場合はクラウド事業者名も
併記し、「通過した地域」として送信元→受信側の流れを示します。</p>
{_card(p, "ok", "ok_bg", "✔ 地域推定もオフライン",
       "地域は IP アドレスの割当ブロック(IANA/RIR)と逆引きホスト名の国コードから、"
       "内蔵データだけで推定します。外部の位置情報サービスには一切問い合わせません。"
       "あくまで概略で、VPN や中継サーバー経由の場合は実際の所在地と異なります。")}
<p class="muted">注意: Received ヘッダーの送信者側(番号の大きい側)は偽造できます。
確実に信頼できるのは自分の利用しているメールサーバーが追記した記録だけです。</p>
"""


def _page_security(p: dict) -> str:
    return f"""
<h1>セキュリティ機能一覧</h1>
<p class="lead">AbyssPeek が自動でチェックしている項目です。</p>

<h2>差出人の偽装チェック</h2>
<ul>
  <li>差出人名義(表示名)とメールアドレスのドメインの不一致</li>
  <li>表示名に別のメールアドレスやドメインを埋め込む偽装</li>
  <li>公式ドメインに酷似したドメイン(<b>amaz0n</b> / <b>paypa1</b> など数字・記号での置換=ホモグリフ)</li>
  <li>正規ブランド名を含む非公式ドメイン、Punycode (xn--) や非 ASCII ドメイン</li>
  <li>ランダムな英数字の使い捨てアドレス・ドメインの検出</li>
  <li>金融機関・公的機関を名乗るフリーメール、返信先 (Reply-To) のフリーメール誘導</li>
</ul>

<h2>HTML メール経由の攻撃検査</h2>
<ul>
  <li>本文内のスクリプト (JavaScript) やイベントハンドラの埋め込み</li>
  <li>ID・パスワードを直接盗む外部送信フォーム</li>
  <li>自動リダイレクト (meta refresh) や外部埋め込み (iframe)</li>
  <li>「表示上の URL」と「実際のリンク先」が異なるリンクのすり替え</li>
</ul>

<h2>URL・添付ファイルの検査</h2>
<ul>
  <li>Punycode / IP アドレス直接指定 / URL 内の @ 記号 / 悪用されやすい TLD / 短縮 URL</li>
  <li>実行形式 (.exe .js .lnk 等) やマクロ付き Office 文書などのマルウェア添付</li>
  <li>二重拡張子 (invoice.pdf.exe など) で実行ファイルを偽装した添付</li>
  <li>すべての URL を hxxp / [.] 形式に無害化して表示</li>
</ul>

<h2>認証・その他のチェック</h2>
<ul>
  <li>SPF / DKIM / DMARC 認証の結果評価(DMARC 失敗は強いなりすまし兆候)</li>
  <li>「緊急」「アカウント停止」など、受信者を焦らせる文言の検出(日英対応)</li>
  <li>SpamAssassin 等のスパム判定ヘッダー (X-Spam-Status) の読み取り</li>
  <li>配送時刻の逆行・送信日時の偽装など Received ヘッダーの矛盾検出</li>
</ul>

{_card(p, "ok", "ok_bg", "✔ プライバシー設計",
       "解析はすべて手元の PC 内で完結します。ネットワーク通信を行わないため、"
       "「開封確認」や「追跡リンク」を踏んでしまう心配なく解析できます。")}
"""


def _page_faq(p: dict) -> str:
    return f"""
<h1>ヒントと FAQ</h1>

<h2>Q. 「問題なし」なら安全ですか?</h2>
<p>A. いいえ。<b>「既知の危険パターンが見つからなかった」という意味</b>であり、安全の保証では
ありません。正規サービスを装った巧妙なメールは認証を通過する場合もあります。
最終判断は「心当たりがあるか」「公式アプリ・ブックマークから確認できるか」で行ってください。</p>

<h2>Q. リスク「高」と判定されたメールはどうすればいい?</h2>
<p>A. リンクや添付ファイルを開かず、メールソフト上で迷惑メール報告をして削除してください。
実在のサービスを騙っている場合は、その<b>公式サイトに自分でアクセスして</b>本物の通知が
あるか確認するのが安全です。</p>

<h2>Q. 本文が表示されません</h2>
<p>A. ヘッダー部分だけをコピーした場合、本文は含まれないため表示されません(正常な動作です)。
本文も解析したい場合は「メッセージのソース」全体をコピーしてください。</p>

<h2>Q. 貼り付けた内容はどこかに送信されますか?</h2>
<p>A. 送信されません。解析はすべてローカルで完結し、保存もユーザーが明示的に
「保存」操作をしたときだけ行われます。</p>

<h2>安全に使うためのヒント</h2>
<ul>
  <li>怪しいメールは<b>本文を開かずに</b>ヘッダーだけコピーするのが理想です。</li>
  <li>HTML メールの画像読み込みは開封の事実を送信者に伝えます。メールソフト側で自動読み込みをオフにしましょう。</li>
  <li>無害化表示 (hxxp) を解除して URL を開くことは絶対に避けてください。</li>
  <li>判定に迷ったら、所属組織の情報システム部門やセキュリティ窓口に相談を。</li>
</ul>

<p class="muted">AbyssPeek は判断を助けるツールであり、ウイルス対策ソフトの代わりにはなりません。</p>
"""
