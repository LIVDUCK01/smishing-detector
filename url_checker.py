import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8')

import re
import os
import socket
import ipaddress
from urllib.parse import urlparse
import requests

# 1. 텍스트 내 웹 링크(단축 링크 포함)를 빠짐없이 추출하기 위한 정규표현식
URL_PATTERN = re.compile(
    r'(?:https?:\/\/|www\.)[a-zA-Z0-9.\-_]+(?::\d+)?(?:\/[^\s가-힣]*)?'
    r'|[a-zA-Z0-9.-]+\.(?:com|net|org|kr|xyz|top|site|online|run|club|cc|me)(?:\/[^\s가-힣]*)?',
    re.IGNORECASE
)

# 스미싱 및 피싱 제작에 자주 악용되는 고위험 무료/저가 TLD 목록
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'site', 'online', 'run',
    'buzz', 'work', 'tk', 'ml', 'ga', 'cf', 'gq', 'cc'
}

# ─────────────────────────────────────────────
# VirusTotal 설정
# API 키는 코드에 직접 적지 않고 환경변수로 받습니다.
# (PowerShell 예시) $env:VIRUSTOTAL_API_KEY="발급받은키"
# ─────────────────────────────────────────────
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{}"
VT_TIMEOUT = 4  # 초. 너무 길면 /diagnose 응답이 느려지므로 짧게 제한.

# 같은 실행(프로세스) 안에서 동일 도메인을 반복 조회하지 않도록 하는 간단한 메모리 캐시
_vt_cache = {}


def extract_urls(text: str) -> list:
    """본문에서 모든 URL 문자열을 리스트로 추출"""
    matches = URL_PATTERN.findall(text)
    urls = []
    for url in matches:
        # http/https가 없는 경우 연결 추적을 위해 기본 스키마 부여
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        urls.append(url)
    return urls


def resolve_redirect(url: str, timeout: int = 3) -> str:
    """단축 링크(bit.ly 등)의 원본 서버 최종 리디렉션 목적지 추적"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15'
    }
    try:
        response = requests.head(url, headers=headers, allow_redirects=True, timeout=timeout)
        return response.url
    except requests.RequestException:
        return url


def is_ip_address(domain: str) -> bool:
    """도메인 자리에 숫자 IP를 직접 사용하는 비정상 패턴 탐지"""
    host = domain.split(':')[0]
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        return False


def is_private_host(hostname: str) -> bool:
    """사설/로컬 IP인지 확인 (192.168.x.x, 10.x.x.x, 127.0.0.1 등).
    이런 주소는 외부 VirusTotal이 알 수 없는 내부망 주소라 조회해도 의미가 없고,
    괜히 API 호출 시간만 늘어나므로 VT 조회 자체를 건너뜁니다."""
    try:
        ip = ipaddress.ip_address(hostname.split(':')[0])
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False  # IP 형식이 아니면(=일반 도메인) 사설 여부 판단 대상 아님


def check_virustotal(hostname: str) -> dict | None:
    """VirusTotal에 도메인 평판 조회. 실패/키없음/타임아웃이면 None 반환
    (호출부에서 None이면 VT 점수 없이 자체 규칙 판정만 사용)."""
    if not VT_API_KEY:
        return None

    if hostname in _vt_cache:
        return _vt_cache[hostname]

    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.get(
            VT_DOMAIN_URL.format(hostname),
            headers=headers,
            timeout=VT_TIMEOUT,
        )
        if res.status_code != 200:
            _vt_cache[hostname] = None
            return None

        stats = (
            res.json()
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        result = {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }
        _vt_cache[hostname] = result
        return result
    except requests.RequestException:
        _vt_cache[hostname] = None
        return None


def analyze_url(url: str) -> dict:
    """개별 URL에 대한 보안 위험 지표 분석"""
    final_url = resolve_redirect(url)
    parsed = urlparse(final_url)

    domain = parsed.netloc.lower()
    hostname = (parsed.hostname or "").lower()
    path = parsed.path.lower()

    risk_factors = []
    risk_score = 0  # 0~100점 척도

    # 지표 1: 호스트가 도메인 네임이 아닌 IP 주소인 경우 (고위험)
    host_is_ip = is_ip_address(domain)
    if host_is_ip:
        risk_factors.append("도메인 대신 숫자 IP 주소 직접 사용")
        risk_score += 40

    # 지표 2: 악성 도메인 단골 TLD 사용 여부
    tld = domain.split('.')[-1]
    if tld in SUSPICIOUS_TLDS:
        risk_factors.append(f"고위험 최상위 도메인(.{tld}) 사용")
        risk_score += 30

    # 지표 3: 비정상 특수 포트 번호 명시
    if parsed.port and parsed.port not in [80, 443]:
        risk_factors.append(f"비표준 네트워크 포트({parsed.port}) 사용")
        risk_score += 20

    # 지표 4: URL 내 악성 APK/실행 파일 직접 다운로드 유도
    if any(path.endswith(ext) for ext in ['.apk', '.exe', '.zip', '.rar']):
        risk_factors.append("실행형/압축 악성 파일 직접 다운로드 경로 포함")
        risk_score += 50

    # 지표 5: 사용자 인증 정보 탈취를 위한 @ 기호 난독화
    if '@' in url:
        risk_factors.append("URL 난독화를 위한 @ 기호 포함")
        risk_score += 25

    # 지표 6: VirusTotal 평판 조회 (사설 IP는 건너뜀 — 조회해도 무의미 + 속도 저하)
    vt_result = None
    if hostname and not host_is_ip and not is_private_host(hostname):
        vt_result = check_virustotal(hostname)
        if vt_result:
            malicious = vt_result["malicious"]
            suspicious = vt_result["suspicious"]
            if malicious > 0:
                risk_factors.append(
                    f"VirusTotal: {malicious}개 보안업체가 악성으로 탐지"
                )
                risk_score += min(50, malicious * 10)
            elif suspicious > 0:
                risk_factors.append(
                    f"VirusTotal: {suspicious}개 보안업체가 의심스러움으로 탐지"
                )
                risk_score += min(25, suspicious * 5)

    return {
        "original_url": url,
        "final_url": final_url,
        "is_redirected": url != final_url,
        "risk_score": min(risk_score, 100),
        "risk_factors": risk_factors,
        "virustotal": vt_result,  # None이면 조회 안 됨(키 없음/사설IP/실패)
    }


def check_message_urls(text: str) -> dict:
    """문자 메시지 전체를 받아 URL 존재 여부 및 위험도 종합 평가"""
    urls = extract_urls(text)

    if not urls:
        return {
            "has_url": False,
            "url_count": 0,
            "results": []
        }

    results = [analyze_url(u) for u in urls]
    max_risk = max(r["risk_score"] for r in results)

    return {
        "has_url": True,
        "url_count": len(urls),
        "max_risk_score": max_risk,
        "results": results
    }


# 로컬 단독 테스트용 진입점
if __name__ == "__main__":
    sample_sms = (
        "[국제발신] 해외직구 결제 승인 완료. 본인 아닐 시 확인 요망: "
        "http://192.168.1.100:8080/secure/update.apk"
    )

    print("--- 테스트 메시지 분석 시작 ---")
    analysis = check_message_urls(sample_sms)

    import json
    print(json.dumps(analysis, indent=2, ensure_ascii=False))
