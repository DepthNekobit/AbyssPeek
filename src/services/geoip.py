"""オフラインの簡易 IP ジオロケーション。

外部通信を一切行わない設計を守るため、精密な GeoIP DB ではなく、
IANA/RIR 由来の IPv4 /8 割当を大陸(地域)単位に集約した内蔵テーブルと、
逆引きホスト名の ccTLD から国を推定する方式を用いる。あくまで概略。

/8 テーブルは ipverse/country-ip-blocks (CC0 1.0, 5 RIR の delegated 統計を
国別に集約したデータ) を tools/generate_geoip_table.py で /8 単位に集計して生成した
(実行時はこの内蔵テーブルのみ使用)。
"""

from dataclasses import dataclass
import ipaddress
import re


# octet(第1オクテット) -> "REGION" または "REGION:CC"
_OCTET_REGION = {
    1: 'AS', 2: 'EU', 3: 'NA:US', 4: 'NA:US', 5: 'EU', 6: 'NA:US', 7: 'NA:US', 8: 'NA',
    9: 'NA:US', 11: 'NA:US', 12: 'NA:US', 13: 'NA:US', 14: 'AS', 15: 'NA:US', 16: 'NA:US', 17: 'NA:US',
    18: 'NA:US', 19: 'NA:US', 20: 'NA:US', 21: 'NA:US', 22: 'NA:US', 23: 'NA:US', 24: 'NA:US', 25: 'EU:GB',
    26: 'NA:US', 27: 'AS', 28: 'NA:US', 29: 'NA:US', 30: 'NA:US', 31: 'EU', 32: 'NA:US', 33: 'NA:US',
    34: 'NA:US', 35: 'NA:US', 36: 'AS:CN', 37: 'EU', 38: 'NA:US', 39: 'AS', 40: 'NA:US', 41: 'AF',
    42: 'AS', 43: 'AS', 44: 'NA:US', 45: 'NA', 46: 'EU', 47: 'NA:US', 48: 'NA', 49: 'AS',
    50: 'NA:US', 51: 'NA', 52: 'NA:US', 53: 'EU:DE', 54: 'NA:US', 55: 'NA:US', 56: 'NA:US', 57: 'EU',
    58: 'AS', 59: 'AS', 60: 'AS', 61: 'AS', 62: 'EU', 63: 'NA:US', 64: 'NA:US', 65: 'NA:US',
    66: 'NA:US', 67: 'NA:US', 68: 'NA:US', 69: 'NA:US', 70: 'NA:US', 71: 'NA:US', 72: 'NA:US', 73: 'NA:US',
    74: 'NA:US', 75: 'NA:US', 76: 'NA:US', 77: 'EU', 78: 'EU', 79: 'EU', 80: 'EU', 81: 'EU',
    82: 'EU', 83: 'EU', 84: 'EU', 85: 'EU', 86: 'EU', 87: 'EU', 88: 'EU', 89: 'EU',
    90: 'EU', 91: 'EU', 92: 'EU', 93: 'EU', 94: 'EU', 95: 'EU', 96: 'NA:US', 97: 'NA:US',
    98: 'NA:US', 99: 'NA:US', 100: 'NA:US', 101: 'AS', 102: 'AF', 103: 'AS', 104: 'NA:US', 105: 'AF',
    106: 'AS', 107: 'NA:US', 108: 'NA:US', 109: 'EU', 110: 'AS', 111: 'AS', 112: 'AS', 113: 'AS',
    114: 'AS', 115: 'AS', 116: 'AS', 117: 'AS', 118: 'AS', 119: 'AS', 120: 'AS', 121: 'AS',
    122: 'AS', 123: 'AS', 124: 'AS', 125: 'AS', 126: 'AS:JP', 128: 'NA:US', 129: 'NA:US', 130: 'NA',
    131: 'NA', 132: 'NA', 133: 'AS:JP', 134: 'NA', 135: 'NA:US', 136: 'NA:US', 137: 'NA', 138: 'NA',
    139: 'NA', 140: 'NA', 141: 'EU', 142: 'NA:CA', 143: 'NA:US', 144: 'NA', 145: 'EU:NL', 146: 'NA',
    147: 'NA', 148: 'NA', 149: 'NA', 150: 'AS', 151: 'EU', 152: 'NA', 153: 'AS', 154: 'AF',
    155: 'NA:US', 156: 'NA', 157: 'NA', 158: 'NA', 159: 'NA', 160: 'NA', 161: 'NA', 162: 'NA:US',
    163: 'AS', 164: 'NA', 165: 'NA', 166: 'NA:US', 167: 'NA:US', 168: 'NA:US', 169: 'NA:US', 170: 'NA:US',
    171: 'AS', 172: 'NA', 173: 'NA:US', 174: 'NA:US', 175: 'AS', 176: 'EU', 177: 'SA:BR', 178: 'EU',
    179: 'SA:BR', 180: 'AS', 181: 'SA', 182: 'AS', 183: 'AS:CN', 184: 'NA:US', 185: 'EU', 186: 'SA',
    187: 'SA', 188: 'EU', 189: 'SA', 190: 'SA', 191: 'SA', 192: 'NA', 193: 'EU', 194: 'EU',
    195: 'EU', 196: 'AF', 197: 'AF', 198: 'NA:US', 199: 'NA:US', 200: 'SA', 201: 'SA', 202: 'AS',
    203: 'AS', 204: 'NA:US', 205: 'NA:US', 206: 'NA:US', 207: 'NA:US', 208: 'NA:US', 209: 'NA:US', 210: 'AS',
    211: 'AS', 212: 'EU', 213: 'EU', 214: 'NA:US', 215: 'NA:US', 216: 'NA:US', 217: 'EU', 218: 'AS',
    219: 'AS', 220: 'AS', 221: 'AS', 222: 'AS', 223: 'AS',
}

REGION_JA = {
    "AS": "アジア太平洋",
    "EU": "ヨーロッパ・中東",
    "NA": "北米",
    "SA": "中南米",
    "AF": "アフリカ",
    "OC": "オセアニア",
}
REGION_FLAG = {
    "AS": "🌏", "EU": "🌍", "NA": "🌎", "SA": "🌎", "AF": "🌍", "OC": "🌏",
}

# 国コード -> (日本語名, 国旗絵文字)
COUNTRY_JA = {
    "JP": ("日本", "🇯🇵"), "US": ("アメリカ", "🇺🇸"), "CN": ("中国", "🇨🇳"),
    "KR": ("韓国", "🇰🇷"), "GB": ("イギリス", "🇬🇧"), "DE": ("ドイツ", "🇩🇪"),
    "FR": ("フランス", "🇫🇷"), "NL": ("オランダ", "🇳🇱"), "RU": ("ロシア", "🇷🇺"),
    "CA": ("カナダ", "🇨🇦"), "BR": ("ブラジル", "🇧🇷"), "IN": ("インド", "🇮🇳"),
    "SG": ("シンガポール", "🇸🇬"), "HK": ("香港", "🇭🇰"), "TW": ("台湾", "🇹🇼"),
    "AU": ("オーストラリア", "🇦🇺"), "IT": ("イタリア", "🇮🇹"), "ES": ("スペイン", "🇪🇸"),
    "PL": ("ポーランド", "🇵🇱"), "UA": ("ウクライナ", "🇺🇦"), "TR": ("トルコ", "🇹🇷"),
    "VN": ("ベトナム", "🇻🇳"), "TH": ("タイ", "🇹🇭"), "ID": ("インドネシア", "🇮🇩"),
    "PH": ("フィリピン", "🇵🇭"), "MY": ("マレーシア", "🇲🇾"), "ZA": ("南アフリカ", "🇿🇦"),
    "NG": ("ナイジェリア", "🇳🇬"), "EG": ("エジプト", "🇪🇬"), "IR": ("イラン", "🇮🇷"),
    "MX": ("メキシコ", "🇲🇽"), "AR": ("アルゼンチン", "🇦🇷"), "CH": ("スイス", "🇨🇭"),
    "SE": ("スウェーデン", "🇸🇪"), "NO": ("ノルウェー", "🇳🇴"), "FI": ("フィンランド", "🇫🇮"),
    "CZ": ("チェコ", "🇨🇿"), "RO": ("ルーマニア", "🇷🇴"), "MA": ("モロッコ", "🇲🇦"), "TN": ("チュニジア", "🇹🇳"), "PK": ("パキスタン", "🇵🇰"),
    "BD": ("バングラデシュ", "🇧🇩"), "SA": ("サウジアラビア", "🇸🇦"), "AE": ("アラブ首長国連邦", "🇦🇪"),
    "IL": ("イスラエル", "🇮🇱"), "NZ": ("ニュージーランド", "🇳🇿"),
}

# ccTLD -> 国コード(逆引きホスト名からの推定用。主要国)
CCTLD_COUNTRY = {
    "jp": "JP", "us": "US", "cn": "CN", "kr": "KR", "uk": "GB", "gb": "GB",
    "de": "DE", "fr": "FR", "nl": "NL", "ru": "RU", "ca": "CA", "br": "BR",
    "in": "IN", "sg": "SG", "hk": "HK", "tw": "TW", "au": "AU", "it": "IT",
    "es": "ES", "pl": "PL", "ua": "UA", "tr": "TR", "vn": "VN", "th": "TH",
    "id": "ID", "ph": "PH", "my": "MY", "za": "ZA", "ng": "NG", "eg": "EG",
    "ir": "IR", "mx": "MX", "ar": "AR", "ch": "CH", "se": "SE", "no": "NO",
    "fi": "FI", "cz": "CZ", "ro": "RO", "ma": "MA", "tn": "TN", "pk": "PK",
    "bd": "BD", "sa": "SA", "ae": "AE", "il": "IL", "nz": "NZ", "at": "AT",
    "be": "BE", "dk": "DK", "pt": "PT", "gr": "GR", "ie": "IE", "hu": "HU",
}

# 逆引きホスト名によく現れる大手ホスティング/クラウド事業者
HOSTING_PROVIDERS = (
    ("amazonaws", "Amazon AWS"), ("googleusercontent", "Google Cloud"),
    ("1e100", "Google"), ("azure", "Microsoft Azure"), ("cloudfront", "Amazon CloudFront"),
    ("akamai", "Akamai"), ("ovh", "OVH"), ("hetzner", "Hetzner"),
    ("digitalocean", "DigitalOcean"), ("linode", "Linode"), ("vultr", "Vultr"),
    ("contabo", "Contabo"), ("leaseweb", "LeaseWeb"), ("alibaba", "Alibaba Cloud"),
    ("aliyun", "Alibaba Cloud"), ("tencent", "Tencent Cloud"), ("sakura", "さくらインターネット"),
    ("conoha", "ConoHa"), ("xserver", "エックスサーバー"), ("cloudflare", "Cloudflare"),
)

_PRIVATE_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
              "169.254.0.0/16", "100.64.0.0/10")
)


@dataclass
class GeoInfo:
    label: str          # 表示用(例: "🇯🇵 日本 (アジア太平洋)")
    region: str | None  # AS/EU/... or None
    country: str | None # 国コード or None
    is_private: bool
    approximate: bool    # 地域のみ等の概略か


def describe_ip(ip_str: str, hostname: str | None = None) -> GeoInfo:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return GeoInfo(label="(不明な IP)", region=None, country=None, is_private=False, approximate=True)

    if any(ip in net for net in _PRIVATE_NETS) or ip.is_loopback:
        return GeoInfo(label="内部ネットワーク (LAN)", region=None, country=None, is_private=True, approximate=False)

    if ip.version != 4:
        return GeoInfo(label="IPv6(地域判定は簡易対応外)", region=None, country=None, is_private=False, approximate=True)

    # 逆引きホスト名の ccTLD / 事業者を優先(より確度が高い)
    host_cc = country_from_hostname(hostname) if hostname else None
    provider = provider_from_hostname(hostname) if hostname else None

    octet = int(str(ip).split(".", 1)[0])
    entry = _OCTET_REGION.get(octet)
    region = entry.split(":")[0] if entry else None
    table_cc = entry.split(":")[1] if entry and ":" in entry else None

    country = host_cc or table_cc
    approximate = host_cc is None  # 表テーブルは概略、ホスト名一致なら確度が高い

    parts: list[str] = []
    if country and country in COUNTRY_JA:
        name, flag = COUNTRY_JA[country]
        parts.append(f"{flag} {name}")
    if region:
        region_name = REGION_JA.get(region, "地域不明")
        if country and country in COUNTRY_JA:
            parts.append(f"({region_name})")
        else:
            parts.append(f"{REGION_FLAG.get(region, '🌐')} {region_name}")
    if provider:
        parts.append(f"— {provider}")

    label = " ".join(parts) if parts else "地域を特定できません"
    return GeoInfo(label=label, region=region, country=country, is_private=False, approximate=approximate)


def country_from_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    match = re.search(r"\.([a-z]{2})$", hostname.strip().lower())
    if match:
        return CCTLD_COUNTRY.get(match.group(1))
    return None


def provider_from_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    lowered = hostname.lower()
    for needle, label in HOSTING_PROVIDERS:
        if needle in lowered:
            return label
    return None
