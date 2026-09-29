"""src/services/geoip.py の IPv4 /8 地域テーブル (_OCTET_REGION) を再生成する。

データ元は ipverse/country-ip-blocks (CC0 1.0, パブリックドメイン相当)。
これは 5 つの RIR (AFRINIC / APNIC / ARIN / LACNIC / RIPE NCC) が公開する
delegated 統計を国別に集約したもの。/8 ごとに割当アドレス数を国別に合算し、

- 地域: 国を RIR のサービス地域に対応付け、最も多い地域
- 国  : 1 か国が COUNTRY_SHARE 以上を占める場合のみ付与

として "REGION" または "REGION:CC" を出力する。アプリ本体は実行時に通信せず、
このスクリプトの出力を geoip.py に貼り付けた内蔵テーブルだけを使う。

使い方:
    # 1) データを取得(どちらか)
    git clone --depth 1 https://github.com/ipverse/country-ip-blocks
    #    または Releases の country-ip-blocks.tar.gz を展開
    # 2) テーブルを出力して geoip.py の _OCTET_REGION を置き換える
    python tools/generate_geoip_table.py path/to/country-ip-blocks
"""

from collections import Counter, defaultdict
import ipaddress
from pathlib import Path
import sys

# 1 か国がこの割合以上を占める /8 だけ国コードを付ける
COUNTRY_SHARE = 0.7

# 国コード -> 地域 (RIR のサービス地域に準拠。REGION_JA のキーと対応)
_RIR_COUNTRIES = {
    "AF": (  # AFRINIC: アフリカ
        "ao bf bi bj bw cd cf cg ci cm cv dj dz eg eh er et ga gh gm gn gq gw ke km lr ls"
        " ly ma mg ml mr mu mw mz na ne ng re rw sc sd sl sn so ss st sz td tg tn tz ug yt"
        " za zm zw"
    ),
    "AS": (  # APNIC: アジア太平洋
        "af as au bd bn bt cc ck cn cx fj fm gu hk id in io jp kh ki kp kr la lk mh mm mn"
        " mo mp mv my nc nf np nr nu nz pf pg ph pk pn pw sb sg th tk tl to tv tw vn vu wf ws"
    ),
    "NA": (  # ARIN: 北米(カリブ海の一部を含む)
        "ag ai aq bb bl bm bs bv ca dm gd gp hm jm kn ky lc mf mq ms pm pr tc um us vc vg vi"
    ),
    "SA": (  # LACNIC: 中南米
        "ar aw bo bq br bz cl co cr cu cw do ec fk gf gs gt gy hn ht mx ni pa pe py sr sv sx"
        " tt uy ve"
    ),
    "EU": (  # RIPE NCC: ヨーロッパ・中東・中央アジア
        "ad ae al am at ax az ba be bg bh by ch cy cz de dk ee es fi fo fr gb ge gg gi gl gr"
        " hr hu ie il im iq ir is it je jo kg kw kz lb li lt lu lv mc md me mk mt nl no om pl"
        " ps pt qa ro rs ru sa se si sk sm sy tj tm tr ua uz va ye"
    ),
}
COUNTRY_REGION = {cc: region for region, codes in _RIR_COUNTRIES.items() for cc in codes.split()}


def load_counts(root: Path) -> dict[int, Counter]:
    """/8 (第1オクテット) ごとの {国コード: アドレス数} を返す。"""
    counts: dict[int, Counter] = defaultdict(Counter)
    country_dir = root / "country"
    if not country_dir.is_dir():
        raise SystemExit(f"{country_dir} が見つかりません")

    unknown: list[str] = []
    for path in sorted(country_dir.glob("*/ipv4-aggregated.txt")):
        cc = path.parent.name.lower()
        if cc not in COUNTRY_REGION:
            unknown.append(cc)
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            net = ipaddress.ip_network(line)
            # /8 より大きい集約 (例: /7) は /8 ごとに分割して数える
            subnets = net.subnets(new_prefix=8) if net.prefixlen < 8 else (net,)
            for sub in subnets:
                counts[int(sub.network_address) >> 24][cc.upper()] += sub.num_addresses
    if unknown:
        raise SystemExit(f"地域が未定義の国コードがあります: {', '.join(unknown)}")
    return counts


def build_table(counts: dict[int, Counter]) -> dict[int, str]:
    table: dict[int, str] = {}
    for octet in sorted(counts):
        by_country = counts[octet]
        by_region: Counter = Counter()
        for cc, n in by_country.items():
            by_region[COUNTRY_REGION[cc.lower()]] += n
        region = by_region.most_common(1)[0][0]
        top_cc, top_n = by_country.most_common(1)[0]
        if top_n / sum(by_country.values()) >= COUNTRY_SHARE:
            table[octet] = f"{region}:{top_cc}"
        else:
            table[octet] = region
    return table


def format_table(table: dict[int, str], per_line: int = 8) -> str:
    items = [f"{octet}: '{value}'" for octet, value in table.items()]
    lines = ["_OCTET_REGION = {"]
    for i in range(0, len(items), per_line):
        lines.append("    " + ", ".join(items[i:i + per_line]) + ",")
    lines.append("}")
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    print(format_table(build_table(load_counts(Path(sys.argv[1])))))


if __name__ == "__main__":
    main()
