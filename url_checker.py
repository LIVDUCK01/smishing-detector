# -*- coding: utf-8 -*-
import io
import sys
import os
import re
import ipaddress
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
import requests

# 윈도우 터미널 UTF-8 출력 보정
try:
    if sys.stdout.encoding.lower() != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')
    if sys.stderr.encoding.lower() != 'utf-8':
        sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8')
except Exception:
    pass

# VirusTotal API 키 설정 (환경 변수 우선, 없으면 아래 문자열 직접 입력)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "여기에_발급받은_VIRUSTOTAL_API_KEY_입력")

# ==============================================================================
# 1. URL 정규표현식 (ML 학습 전처리용 vs URL 위험도 추출용 완전 분리)
# ==============================================================================

# [절대 수정 금지] ML 모델(model.pkl) 학습 당시 사용한 원본 전처리 정규식 (재학습 방지)
ML_URL_PATTERN = re.compile(
    r'(?:https?:\/\/|www\.)[a-zA-Z0-9.\-_]+(?::\d+)?(?:\/[^\s가-힣]*)?'
    r'|[a-zA-Z0-9.-]+\.(?:com|net|org|kr|xyz|top|site|online|run|club|cc|me)(?:\/[^\s가-힣]*)?',
    re.IGNORECASE
)

# URL 위험도 분석 추출 전용 정규식 (ML 입력에는 관여하지 않음)
EXTRACT_URL_PATTERN = re.compile(
    r'(?:https?:\/\/|www\.)[a-zA-Z0-9.\-_]+(?::\d+)?(?:\/[^\s가-힣]*)?'
    r'|[a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,10}(?::\d+)?(?:\/[^\s가-힣]*)?',
    re.IGNORECASE
)

# ==============================================================================
# 2. 룰셋 및 블랙/화이트리스트 정의
# ==============================================================================

# 고위험 최상위 도메인(TLD) 풀세트 (74종)
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'site', 'online',
    'run', 'buzz', 'work', 'cc', 'icu', 'fit', 'surf', 'monster', 'vip',
    'rest', 'live', 'link', 'click', 'sbs', 'cfd', 'shop', 'support',
    'loan', 'stream', 'download', 'racing', 'date', 'party', 'review', 'tokyo',
    'info', 'biz', 'mobi', 'pro', 'asia', 'pw', 'ws', 'la', 'to', 'bid',
    'win', 'faith', 'science', 'accountant', 'men', 'trade', 'webcam', 'gdn',
    'mom', 'xin', 'kim', 'red', 'blue', 'pink', 'host', 'space', 'website',
    'press', 'tech', 'store', 'fun', 'world', 'today', 'life', 'guru', 'zone',
    'digital', 'network', 'cloud'
}

# 목적지 은닉 단축 URL 도메인 풀세트 (26종)
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd',
    'me2.do', 'han.gl', 'vvd.bz', 'vo.la', 'url.kr', 'vo.kr',
    'shorturl.at', 'rb.gy', 'ow.ly', 'buff.ly', 'rebrand.ly',
    'tiny.cc', 'bl.ink', 's.id', 'gg.gg', 'zrr.kr', 'tuney.kr',
    'buly.kr', 'asq.kr', 'bit.do', 'goo.gl'
}

# 피싱 페이지 유포에 상습 악용되는 무료 클라우드/PaaS 호스팅 플랫폼 (12종)
FREE_HOSTING_DOMAINS = {
    'firebaseapp.com', 'web.app', 'vercel.app', 'netlify.app',
    'pages.dev', 'glitch.me', 'github.io', 'workers.dev',
    'appspot.com', 'herokuapp.com', 'forms.gle', 'notion.site'
}

# 전 카테고리 스미싱 사칭 키워드 (영문 + 한글)
SPOOF_KEYWORDS = [
    # [카테고리 1] 지원금 / 대출 / 정책자금 / 환급
    'loan', 'fund', 'support', 'subsidy', 'credit', 'bokjiro', 'finance',
    'grant', 'benefit', 'voucher', 'relief', 'refund', 'debt', 'interest',
    '대출', '지원금', '보조금', '생계자금', '정책자금', '소상공인', '긴급지원',
    '한도조회', '저금리', '대환', '정부지원', '복지', '환급', '상환', '채무',

    # [카테고리 2] 택배 / 물류 / 해외직구 통관
    'cj', 'post', 'epost', 'parcel', 'delivery', 'fedex', 'dhl', 'ups',
    'logistics', 'daehan', 'hanjin', 'lotte', 'logen', 'track', 'tracking',
    'shipping', 'freight', 'customs', 'unipass', 'cargo', 'address',
    '택배', '배송', '운송장', '송장', '통관', '관세', '반송', '주소지',
    '미수령', '보관중', '물류', '우체국',

    # [카테고리 3] 금융 / 은행 / 카드 / 결제 승인
    'bank', 'card', 'kb', 'kbstar', 'nh', 'nonghyup', 'shinhan', 'woori',
    'hana', 'ibk', 'kakao', 'kakaobank', 'toss', 'pay', 'naverpay', 'kakaopay',
    'samsung', 'hyundai', 'lottecard', 'bccard', 'transfer', 'billing',
    'invoice', 'payment', 'receipt', 'approve', 'approval', 'overseas',
    '은행', '카드', '결제', '승인', '계좌', '이체', '출금', '한도', '연체',
    '미납', '청구서', '영수증', '해외결제', '거래정지',

    # [카테고리 4] 공공기관 / 사법 / 과태료 / 건강보험
    'police', 'gov', 'court', 'scourt', 'spo', 'nts', 'hometax', 'wetax',
    'nhis', 'nps', 'kisa', 'fss', 'fine', 'penalty', 'ticket', 'violation',
    'summons', 'warrant', 'tax', 'health', 'checkup', 'minwon',
    '경찰', '검찰', '법원', '출석', '사건', '과태료', '범칙금', '위반',
    '단속', '국세청', '세금', '연말정산', '건강보험', '건보', '검진', '민원', '정부24',

    # [카테고리 5] 모바일 청첩장 / 부고장 / 지인 사칭
    'wedding', 'marry', 'invitation', 'invit', 'bride', 'groom',
    'bugo', 'funeral', 'obituary', 'rip', 'condolence', 'memorial',
    '청첩장', '결혼', '모바일청첩장', '부고', '부고장', '조문', '별세', '장례', '빈소', '발인',

    # [카테고리 6] 계정 탈취 / 보안 인증 / 악성 앱 설치 유도
    'login', 'signin', 'verify', 'verification', 'secure', 'security',
    'auth', 'account', 'update', 'cert', 'certificate', 'password', 'passwd',
    'reset', 'unlock', 'suspend', 'alert', 'warning', 'install', 'app',
    'skt', 'kt', 'lgu', 'uplus', 'telecom',
    '로그인', '인증', '본인인증', '보안', '업데이트', '차단', '정지', '해제',
    '비밀번호', '계정', '설치', '어플', '앱설치'
]

# 공식 화이트리스트 (기관/기업 메인 도메인 - 오탐 0% 방어막)
TRUSTED_DOMAINS = [
    "naver.com", "kakao.com", "daum.net", "google.com", "google.co.kr",
    "apple.com", "microsoft.com", "gov.kr", "epost.go.kr", "post.go.kr",
    "police.go.kr", "spo.go.kr", "scourt.go.kr", "hometax.go.kr", "nts.go.kr",
    "wetax.go.kr", "customs.go.kr", "nhis.or.kr", "nps.or.kr", "comwel.or.kr",
    "ei.go.kr", "fss.or.kr", "kisa.or.kr", "cjlogistics.com", "hanjin.co.kr",
    "hanjin.com", "lotteglogis.com", "ilogen.com", "logen.com", "kdexp.com",
    "daesinlogistics.co.kr", "cupost.co.kr", "cvsnet.co.kr", "kbstar.com",
    "shinhan.com", "wooribank.com", "hanabank.com", "nhbank.com", "nonghyup.com",
    "ibk.co.kr", "kakaobank.com", "toss.im", "tossbank.com", "kbanknow.com",
    "sc.co.kr", "citi.co.kr", "suhyup-bank.com", "epostbank.go.kr",
    "shinhancard.com", "kbcard.com", "samsungcard.com", "hyundaicard.com",
    "lottecard.co.kr", "wooricard.com", "hanacard.co.kr", "bccard.com",
    "nhcard.co.kr", "kiwoom.com", "miraeasset.com", "nhqv.com",
    "samsungpop.com", "kbsec.com", "shinhansec.com", "koreainvestment.com",
    "daishin.com", "sktelecom.com", "tworld.co.kr", "kt.com", "lguplus.com",
    "uplus.co.kr", "sk7mobile.com", "ktmmobile.com", "uplussave.com",
    "coupang.com", "gmarket.co.kr", "auction.co.kr", "11st.co.kr", "ssg.com",
    "lotteon.com", "musinsa.com", "kurly.com", "interpark.com", "kream.co.kr",
    "oliveyoung.co.kr", "starbucks.co.kr", "baemin.com", "yogiyo.co.kr",
    "yanolja.com", "goodchoice.kr", "cgv.co.kr", "lottecinema.co.kr",
    "megabox.co.kr", "yes24.com", "kyobobook.co.kr", "aladin.co.kr",
    "gsshop.com", "hmall.com", "daiso.co.kr", "korail.com", "letskorail.com",
    "srail.or.kr", "barunsoncard.com", "bojagicard.com", "itscard.co.kr",
    "cardq.co.kr", "deardeer.kr", "premierpaper.co.kr", "fromtoday.co.kr",
    "fillmaker.com", "e-skyn.go.kr", "samga.co.kr", "maeumbugo.co.kr",
    "k-bugo.com", "snuh.org", "amc.seoul.kr", "samsunghospital.com", "yuhs.or.kr"
]


# ==============================================================================
# 3. 전처리 및 보조 검증 함수
# ==============================================================================

def strip_urls_for_ml(text: str) -> str:
    """텍스트 내 URL을 제거하거나 머신러닝 학습/추론용으로 전처리 (학습 당시 정규식 유지)"""
    if not isinstance(text, str):
        return ""
    cleaned_text = ML_URL_PATTERN.sub("[URL]", text)
    return cleaned_text


def extract_urls(text: str) -> list:
    """본문에서 모든 URL 문자열을 리스트로 추출 (URL 추출 전용 정규식 사용)"""
    if not isinstance(text, str):
        return []
    matches = EXTRACT_URL_PATTERN.findall(text)
    urls = []
    trailing_chars = '.,;:!?)>"\''
    for url in matches:
        url = url.rstrip(trailing_chars)
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        urls.append(url)
    return urls


def resolve_redirect(url: str, timeout: float = 1.0) -> str:
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
    """표준 IPv4/IPv6 및 변형 10진수/16진수 IP 주소 탐지"""
    clean_host = domain.split(':')[0].strip('[]')
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    if clean_host.isdigit() and len(clean_host) >= 8:
        return True
    if clean_host.startswith('0x') and '.' in clean_host:
        return True

    return False


def is_trusted_official_domain(host: str) -> bool:
    """공식 화이트리스트 검증 (종단 일치 + 국가 공인 정부·대학 도메인 .go.kr/.ac.kr/.mil.kr)"""
    if host.endswith(('.go.kr', '.ac.kr', '.mil.kr')):
        return True
    return any(host == trusted or host.endswith('.' + trusted) for trusted in TRUSTED_DOMAINS)


def _get_apex_domain(host: str) -> str:
    """RDAP 도메인 생성일 조회를 위한 최상위 등록 도메인(Apex Domain) 추출"""
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    multi_slds = {'co.kr', 'or.kr', 'go.kr', 'ac.kr', 'ne.kr', 're.kr', 'pe.kr', 'co.jp', 'or.jp', 'co.uk'}
    if '.'.join(parts[-2:]) in multi_slds and len(parts) >= 3:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def check_domain_age_rdap(host: str, timeout: float = 0.5) -> dict:
    """IANA/공식 RDAP 조회를 통한 신규 개설 도메인(30일 이내 제로데이 피싱) 탐지"""
    apex = _get_apex_domain(host)
    rdap_url = f"https://rdap.org/domain/{apex}"
    try:
        res = requests.get(rdap_url, timeout=timeout, headers={"User-Agent": "SMSGuard-Detection-Agent/1.0"})
        if res.status_code != 200:
            return {"checked": False}
        data = res.json()
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                reg_str = ev["eventDate"].replace("Z", "+00:00")
                reg_dt = datetime.fromisoformat(reg_str)
                if reg_dt.tzinfo is None:
                    reg_dt = reg_dt.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - reg_dt).days
                return {"checked": True, "age_days": age_days, "is_new": 0 <= age_days <= 30}
        return {"checked": False}
    except Exception:
        return {"checked": False}


def match_smart_keywords(target_text: str) -> list:
    """부분 문자열 오탐 방지 + 붙여쓴 복합 단어 포착"""
    matched = []
    tokens = set(re.split(r'[^a-zA-Z0-9가-힣]+', target_text.lower()))

    for kw in SPOOF_KEYWORDS:
        if re.search(r'[가-힣]', kw):
            if kw in target_text:
                matched.append(kw)
        elif len(kw) <= 3:
            if kw in tokens:
                matched.append(kw)
        else:
            if kw in target_text:
                matched.append(kw)
    return list(dict.fromkeys(matched))


def check_virustotal_domain(domain: str, timeout: float = 0.5) -> dict:
    """VirusTotal v3 API를 통해 도메인 평판 데이터 조회"""
    if not VIRUSTOTAL_API_KEY or "여기에_" in VIRUSTOTAL_API_KEY:
        return {"success": False, "reason": "API 키 미설정 (자체 4-Layer 엔진 단독 처리)"}

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


# ==============================================================================
# 4. 핵심 4-Layer 정밀 검증 엔진
# ==============================================================================

def analyze_url(url: str, network: bool = True) -> dict:
    """개별 URL 보안 분석 (4-Layer 정적 엔진 + 화이트리스트 + RDAP 도메인 연령 + 조건부 VT 연동)"""
    analysis_start = time.perf_counter()
    decoded_raw_url = unquote(url)
    
    initial_parsed = urlparse(decoded_raw_url if decoded_raw_url.startswith(('http://', 'https://')) else 'http://' + decoded_raw_url)
    initial_host = (initial_parsed.hostname or initial_parsed.netloc).lower()

    # 공식 화이트리스트 조기 반환 (0.01ms 통과, 오탐 0%)
    if is_trusted_official_domain(initial_host):
        total_latency = round((time.perf_counter() - analysis_start) * 1000, 2)
        return {
            "original_url": url,
            "final_url": url,
            "is_redirected": False,
            "risk_score": 0,
            "risk_level": "정상 (안전)",
            "risk_factors": ["공식 인증 도메인 화이트리스트 통과"],
            "vt_checked": False,
            "vt_info": "공식 화이트리스트 조기 통과로 외부 API 조회 생략",
            "latency_ms": total_latency,
            "timing_ms": total_latency,
            "external_mode": "network" if network else "offline"
        }

    # 단축 URL일 때만 리다이렉트 추적 (fast 모드에서는 생략)
    is_known_shortener = (
        initial_host in SHORTENER_DOMAINS or 
        any(initial_host.endswith('.' + s) for s in SHORTENER_DOMAINS)
    )

    if is_known_shortener and network:
        final_url = resolve_redirect(decoded_raw_url, timeout=1.0)
    else:
        final_url = decoded_raw_url

    final_url = unquote(final_url)
    parsed = urlparse(final_url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or parsed.netloc).lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_target = f"{host}{path}?{query}"

    risk_factors = []
    risk_score = 0

    # --- 1단계: 자체 4-Layer 정적 규칙 검사 (Fast Path) ---

    # 지표 1: IP 주소 직접 접근
    if is_ip_address(host):
        risk_factors.append("도메인 대신 숫자/변형 IP 주소 직접 사용")
        risk_score += 50

    # 지표 2: 고위험 TLD
    host_parts = host.split('.')
    tld = host_parts[-1] if len(host_parts) > 1 else ''
    is_bad_tld = tld in SUSPICIOUS_TLDS
    if is_bad_tld:
        risk_factors.append(f"고위험 최상위 도메인(.{tld}) 사용")
        risk_score += 40

    # 지표 3: 공식 브랜드 도메인 기만 사칭
    if any(trusted in host for trusted in TRUSTED_DOMAINS) and not is_trusted_official_domain(host):
        risk_factors.append("공식 기관 도메인을 위장 도용한 서브도메인 사칭 구조 감지")
        risk_score += 50

    # 지표 4: 추적 회피형 단축 URL
    if is_known_shortener:
        risk_factors.append(f"추적 회피형 단축 URL({host}) 사용")
        risk_score += 35

    # 지표 5: 무료 클라우드 호스팅 악용
    is_free_cloud = any(host == cloud or host.endswith('.' + cloud) for cloud in FREE_HOSTING_DOMAINS)
    if is_free_cloud:
        risk_factors.append(f"무료 클라우드/PaaS 호스팅 서비스({host}) 악용 감지")
        risk_score += 40

    # 지표 6: 악성 APK 및 실행 파일 다운로드 경로
    dangerous_exts = ['.apk', '.exe', '.zip', '.rar', '.scr', '.bat', '.msi', '.dmg', '.ipa', '.jar']
    if any(ext in path or ext in query for ext in dangerous_exts):
        risk_factors.append("실행형/압축 악성 파일(.apk 등) 다운로드 유도 경로 감지")
        risk_score += 65

    # 지표 7: 퓨니코드 호모그래프 시각 기만 감지
    if host.startswith('xn--') or '.xn--' in host:
        risk_factors.append("유사 문자 시각 기만(퓨니코드 호모그래프) 도메인 감지")
        risk_score += 50

    # 지표 8: @ 난독화
    if '@' in final_url:
        risk_factors.append("URL 난독화를 위한 @ 기호 포함")
        risk_score += 35

    # 지표 9: 하이픈(-) 다중 사용 (3개 이상은 25점, 2개는 단독 오탐 방지용 15점)
    if host.count('-') >= 3:
        risk_factors.append("기관 사칭 기만 목적의 과도한 하이픈(-) 사용")
        risk_score += 25
    elif host.count('-') == 2:
        risk_factors.append("다중 하이픈(-) 도메인 구조 감지")
        risk_score += 15

    # 지표 10: 다중 서브도메인 난독화 (.co.kr 등 정상 www.xxx.co.kr 오탐 방지)
    kr_second_level = ('.co.kr', '.or.kr', '.go.kr', '.ac.kr', '.ne.kr', '.re.kr', '.pe.kr')
    min_sub_parts = 5 if host.endswith(kr_second_level) else 4
    if len(host_parts) >= min_sub_parts and not is_ip_address(host):
        risk_factors.append("신뢰 기관 위장용 다중 서브도메인 사용")
        risk_score += 20

    # 지표 11: 비표준 포트
    if parsed.port and parsed.port not in [80, 443]:
        risk_factors.append(f"비표준 네트워크 포트({parsed.port}) 사용")
        risk_score += 25

    # 지표 12: 비암호화 평문 HTTP 연결 의심
    if scheme == 'http' and not is_trusted_official_domain(host):
        risk_score += 15
        risk_factors.append("보안 암호화(HTTPS)가 적용되지 않은 평문 연결")

    # 지표 13: 전 카테고리 스마트 키워드 매칭
    matched_kw = match_smart_keywords(full_target)
    if matched_kw:
        kw_preview = ', '.join(matched_kw[:4])
        if len(matched_kw) >= 2:
            risk_factors.append(f"비공식 경로 내 다중 사칭 키워드({kw_preview}) 집중 매칭")
            risk_score += 60
        else:
            risk_factors.append(f"비공식 경로 내 기관 사칭 의심 키워드({kw_preview}) 매칭")
            risk_score += 45

    # 3대 복합 시너지 가중치
    if is_known_shortener and matched_kw:
        risk_factors.append("단축 URL과 사칭 키워드의 복합 악용 감지 (+30)")
        risk_score += 30
    elif is_bad_tld and matched_kw:
        risk_factors.append("고위험 도메인(.xyz/.top 등)과 사칭 키워드의 복합 악용 감지 (+20)")
        risk_score += 20
    elif is_free_cloud and matched_kw:
        risk_factors.append("무료 클라우드 호스팅과 사칭 키워드의 복합 악용 감지 (+25)")
        risk_score += 25

    # --- 2단계: 신규 도메인 연령(RDAP) & VirusTotal API 조건부 연동 ---
    vt_checked = False
    vt_info = ""

    if is_ip_address(host):
        vt_info = "숫자 IP 주소 감지로 외부 API 조회 생략 (최적화)"
    elif not network:
        vt_info = "1차 빠른 분석 모드 (외부 조회 생략)"
    elif risk_score >= 50:
        vt_info = "자체 4-Layer 고위험 패턴 감지로 외부 API 조회 생략 (최적화)"
    else:
        # 2-A. 외형상 정상인 일반 .com/.net 등 미등록 도메인의 개설일(30일 이내 제로데이) 확인
        age_res = check_domain_age_rdap(host, timeout=0.5)
        if age_res.get("checked") and age_res.get("is_new"):
            risk_factors.append(f"개설된 지 {age_res['age_days']}일 된 신규 등록 도메인 감지 (제로데이 피싱 의심)")
            risk_score += 45

        # 2-B. VirusTotal 평판 조회
        vt_res = check_virustotal_domain(host, timeout=0.5)
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

    final_score = min(risk_score, 100)

    if final_score >= 75:
        risk_level = "사칭·스미싱 확실 (위험)"
    elif final_score >= 50:
        risk_level = "고위험 의심 (경고)"
    elif final_score >= 25:
        risk_level = "잠재적 위험 (주의)"
    else:
        risk_level = "정상 (안전)"

    total_latency = round((time.perf_counter() - analysis_start) * 1000, 2)

    return {
        "original_url": url,
        "final_url": final_url,
        "is_redirected": url != final_url,
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "vt_checked": vt_checked,
        "vt_info": vt_info,
        "latency_ms": total_latency,
        "timing_ms": total_latency,
        "external_mode": "network" if network else "offline"
    }


def check_message_urls(text: str, network: bool = True) -> dict:
    """문자 메시지 전체 URL 추출 및 종합 위험도 평가"""
    start_all = time.perf_counter()
    urls = extract_urls(text)
    
    if not urls:
        return {
            "has_url": False,
            "url_count": 0,
            "max_risk_score": 0,
            "results": [],
            "total_latency_ms": round((time.perf_counter() - start_all) * 1000, 2)
        }

    results = [analyze_url(u, network=network) for u in urls]
    max_risk = max(r["risk_score"] for r in results)

    return {
        "has_url": True,
        "url_count": len(urls),
        "max_risk_score": max_risk,
        "results": results,
        "total_latency_ms": round((time.perf_counter() - start_all) * 1000, 2)
    }


if __name__ == "__main__":
    import json
    sample_sms = "[국제발신] 긴급생계지원금 한도조회 안내: http://me2.do/gov-loan-apply"
    print("--- 테스트 메시지 분석 시작 ---")
    analysis = check_message_urls(sample_sms)
    print(json.dumps(analysis, indent=2, ensure_ascii=False))