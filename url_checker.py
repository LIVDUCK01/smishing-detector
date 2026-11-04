import io
import sys
import os
import re
import socket
from urllib.parse import urlparse
import requests

# 윈도우 터미널 UTF-8 출력 보정
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8')

# VirusTotal API 키 설정 (환경 변수 우선, 없으면 아래 문자열 직접 입력)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "여기에_발급받은_VIRUSTOTAL_API_KEY_입력")

# 1. URL 정규표현식
URL_PATTERN = re.compile(
    r'(?:https?:\/\/|www\.)[a-zA-Z0-9.\-_]+(?::\d+)?(?:\/[^\s가-힣]*)?'
    r'|[a-zA-Z0-9.-]+\.(?:com|net|org|kr|xyz|top|site|online|run|club|cc|me)(?:\/[^\s가-힣]*)?',
    re.IGNORECASE
)

# 고위험 TLD 목록
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'site', 'online', 'run', 
    'buzz', 'work', 'tk', 'ml', 'ga', 'cf', 'gq', 'cc'
}

def extract_urls(text: str) -> list:
    """본문에서 모든 URL 문자열을 리스트로 추출"""
    matches = URL_PATTERN.findall(text)
    urls = []
    for url in matches:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        urls.append(url)
    return urls

def resolve_redirect(url: str, timeout: int = 3) -> str:
    """단축 링크의 원본 서버 최종 리디렉션 목적지 추적"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15'
    }
    try:
        response = requests.head(url, headers=headers, allow_redirects=True, timeout=timeout)
        return response.url
    except requests.RequestException:
        return url

def is_ip_address(domain: str) -> bool:
    """도메인 자리에 숫자 IP를 직접 사용하는 패턴 탐지"""
    host = domain.split(':')[0]
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        return False

def check_virustotal_domain(domain: str, timeout: float = 2.0) -> dict:
    """VirusTotal v3 API를 통해 도메인 평판 데이터 조회"""
    if not VIRUSTOTAL_API_KEY or "여기에_" in VIRUSTOTAL_API_KEY:
        return {"success": False, "reason": "API 키 미설정"}

    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "User-Agent": "SMSGuard-Detection-Agent/1.0"
    }

    try:
        res = requests.get(vt_url, headers=headers, timeout=timeout)
        if res.status_code == 200:
            data = res.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "success": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }
        elif res.status_code == 404:
            return {"success": False, "reason": "VirusTotal DB 미등록 도메인"}
        else:
            return {"success": False, "reason": f"HTTP {res.status_code}"}
    except requests.exceptions.Timeout:
        return {"success": False, "reason": "API 응답 시간 초과"}
    except Exception as e:
        return {"success": False, "reason": str(e)}

def analyze_url(url: str) -> dict:
    """개별 URL 보안 분석 (자체 규칙 + 조건부 VirusTotal API 연동)"""
    final_url = resolve_redirect(url)
    parsed = urlparse(final_url)
    
    raw_host = parsed.netloc.lower()
    domain = raw_host.split(':')[0] if ':' in raw_host else raw_host
    path = parsed.path.lower()
    
    risk_factors = []
    risk_score = 0

    # --- 1단계: 자체 정적 규칙 검사 (Fast Path) ---
    
    # 지표 1: 도메인 대신 숫자 IP 주소 직접 사용
    if is_ip_address(domain):
        risk_factors.append("도메인 대신 숫자 IP 주소 직접 사용")
        risk_score += 40

    # 지표 2: 고위험 최상위 도메인 사용
    tld = domain.split('.')[-1] if '.' in domain else ''
    if tld in SUSPICIOUS_TLDS:
        risk_factors.append(f"고위험 최상위 도메인(.{tld}) 사용")
        risk_score += 30

    # 지표 3: 비표준 네트워크 포트 명시
    if parsed.port and parsed.port not in [80, 443]:
        risk_factors.append(f"비표준 네트워크 포트({parsed.port}) 사용")
        risk_score += 20

    # 지표 4: 악성 실행/압축 파일 다운로드 유도
    if any(path.endswith(ext) for ext in ['.apk', '.exe', '.zip', '.rar']):
        risk_factors.append("실행형/압축 악성 파일 직접 다운로드 경로 포함")
        risk_score += 50

    # 지표 5: URL 난독화를 위한 @ 기호 사용
    if '@' in url:
        risk_factors.append("URL 난독화를 위한 @ 기호 포함")
        risk_score += 25

    # --- 2단계: 응답 속도 최적화 & VirusTotal API 조건부 연동 ---
    
    vt_checked = False
    vt_info = ""

    # [속도 최적화 조건]
    # 1. 숫자 IP 주소인 경우 (도메인 조회 API가 불필요하며, 자체 규칙만으로 이미 고위험)
    # 2. 자체 정적 규칙 점수가 이미 50점 이상(명백한 위험)인 경우
    if is_ip_address(domain):
        vt_info = "숫자 IP 주소 감지로 외부 API 조회 생략 (최적화)"
    elif risk_score >= 50:
        vt_info = "명백한 고위험 패턴 감지로 외부 API 조회 생략 (최적화)"
    else:
        # 정상 범위/애매한 도메인만 VirusTotal API 호출 (타임아웃 2.0초 제한)
        vt_res = check_virustotal_domain(domain, timeout=2.0)
        if vt_res.get("success"):
            vt_checked = True
            malicious_cnt = vt_res["malicious"]
            suspicious_cnt = vt_res["suspicious"]

            if malicious_cnt > 0:
                risk_factors.append(f"VirusTotal {malicious_cnt}개 보안 엔진에서 악성(Malicious) 판정")
                risk_score += 60
            elif suspicious_cnt > 0:
                risk_factors.append(f"VirusTotal {suspicious_cnt}개 보안 엔진에서 의심(Suspicious) 판정")
                risk_score += 30
            else:
                vt_info = "VirusTotal 분석 결과 정상 (Clean)"
        else:
            vt_info = f"VirusTotal 미조회 ({vt_res.get('reason', '알 수 없음')})"

    return {
        "original_url": url,
        "final_url": final_url,
        "is_redirected": url != final_url,
        "risk_score": min(risk_score, 100),
        "risk_factors": risk_factors,
        "vt_checked": vt_checked,
        "vt_info": vt_info
    }

def check_message_urls(text: str) -> dict:
    """문자 메시지 전체 URL 추출 및 종합 위험도 평가"""
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

# 로컬 단독 테스트용
if __name__ == "__main__":
    sample_sms = "[국제발신] 해외직구 승인 안내: http://192.168.1.100:8080/check.apk"
    print("--- 테스트 메시지 분석 시작 ---")
    analysis = check_message_urls(sample_sms)
    
    import json
    print(json.dumps(analysis, indent=2, ensure_ascii=False))
