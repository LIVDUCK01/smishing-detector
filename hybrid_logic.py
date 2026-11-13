# -*- coding: utf-8 -*-
"""
계층형(URL 우선 + 무링크 사칭·도박·부업스팸 패턴 및 특수문자 우회 방어) 판정 로직.
main_hybrid.py 와 evaluate.py 가 같은 함수를 쓰므로 서버와 평가 결과가 어긋나지 않는다.
"""
import re
from urllib.parse import urlparse
from official_domains import is_official_url, is_shortener_url

TH_HIGH, TH_MID, TH_VERY_HIGH = 70, 35, 85      # 문구(ML) 점수 기준 (%)
URL_DANGER, URL_SUSPECT = 50, 20                 # URL 위험도 점수 기준

# 정상 메신저 초대 도메인 (단축 URL 오탐 방지)
MESSENGER_DOMAINS = ('t.me', 'open.kakao.com')

# 무링크 스미싱 탐지용 핵심 패턴 (지인 사칭 송금/액정 파손 + 검찰/수사관 사칭)
LINKLESS_IMPERSONATION_PATTERNS = [
    r'(?:엄마|아빠|이모|고모|삼촌|조카|딸|아들).*(?:폰|휴대폰|핸드폰).*(?:바꿔|고장|액정|수리)',
    r'(?:대신\s*송금|급한\s*결제|급하게\s*송금|기프트\s*카드|문화\s*상품권|핀\s*번호|원격\s*제어|팀뷰어)',
    r'(?:검찰|검찰청|지검|수사관|경찰청|금융감독원|금감원).*(?:범죄|연루|명의\s*도용|대포\s*통장|구속|출석|계좌)'
]

# 불법 도박·스포츠토토 및 과장 부업/재택알바 스팸 탐지 패턴 (리딩방·투자권유는 제외 유지)
LINKLESS_SPAM_PATTERNS = [
    r'(?:바카라|카지노|꽁머니|사설\s*토토|파워볼|첫충|매충|환전\s*보장|보증\s*업체)',
    r'(?:스포츠\s*분석|무료\s*픽|유료\s*픽|픽스터|배당률|프로토\s*분석)',
    r'(?:재택\s*알바|재택\s*근무|부업\s*안내|리뷰\s*작성).*(?:일급|월\s*\d+만원|당일\s*지급|고수익|초보\s*가능)'
]

# 정상 카드/계좌 승인 알림 판별 패턴 (회신 번호나 사칭 유도어가 없을 때만 안전 처리)
NORMAL_CARD_ALERT_PATTERN = re.compile(r'(?:승인|일시불|할부|출금|입금|잔액).*[\d,]+원')
CALLBACK_PHONE_PATTERN = re.compile(r'(?:010|02|031|032|051|053|062|042|052|044|15\d{2}|16\d{2}|18\d{2})[-\s]?\d{3,4}[-\s]?\d{4}')
SCAM_ACTION_WORDS = ['수사관', '검찰', '경찰', '송금', '이체요청', '폰바꿔', '액정', '기프트카드', '본인아닌', '명의도용', '연루']


def _is_messenger_url(url: str) -> bool:
    if not url:
        return False
    u = url if url.startswith(('http://', 'https://')) else 'http://' + url
    host = (urlparse(u).hostname or '').lower()
    return any(host == m or host.endswith('.' + m) for m in MESSENGER_DOMAINS)


def _item_official(d: dict) -> bool:
    """URL 1개가 공식 도메인인지 검증 (official_domains.py + url_checker 화이트리스트 동기화)."""
    if '공식 인증 도메인 화이트리스트 통과' in d.get('risk_factors', []):
        return True
    orig, final = d.get('original_url', ''), d.get('final_url') or d.get('original_url', '')
    if _is_messenger_url(orig) or _is_messenger_url(final):
        return True
    if is_shortener_url(orig):
        return (not is_shortener_url(final)) and is_official_url(final)
    return is_official_url(orig) and is_official_url(final)


def _item_vt_clean(d: dict) -> bool:
    vt = d.get('virustotal')
    return vt is not None and vt.get('malicious', 1) == 0 and vt.get('suspicious', 1) == 0


def link_status(has_url: bool, url_score: float, details: list) -> str:
    """none / dangerous / suspicious / official / verified(VirusTotal) / unverified"""
    if not has_url:
        return 'none'
    if url_score >= URL_DANGER:
        return 'dangerous'
    unresolved = any(
        not _is_messenger_url(d.get('original_url', '')) and
        is_shortener_url(d.get('original_url', '')) and
        is_shortener_url(d.get('final_url') or d.get('original_url', ''))
        for d in details
    )
    if url_score >= URL_SUSPECT or unresolved:
        return 'suspicious'
    if details and all(_item_official(d) for d in details):
        return 'official'
    if details and url_score == 0 and all(_item_vt_clean(d) for d in details):
        return 'verified'
    return 'unverified'


def _is_linkless_smishing(text: str, ml_prob: float) -> bool:
    """URL 없는 문자 중 지인·기관 사칭 등 고위험 무링크 스미싱 판별 (특수문자 우회 방어 포함)"""
    if not text:
        return ml_prob >= TH_HIGH
    clean = re.sub(r'\s+', ' ', text)
    squashed = re.sub(r'[^가-힣a-zA-Z]', '', clean)

    for target in (clean, squashed):
        if any(re.search(pat, target, re.IGNORECASE) for pat in LINKLESS_IMPERSONATION_PATTERNS):
            return True

    if CALLBACK_PHONE_PATTERN.search(clean) and any(w in squashed for w in ['검찰', '수사관', '범죄', '명의도용', '출석', '송금']):
        return True
    return ml_prob >= TH_HIGH


def _is_linkless_spam(text: str) -> bool:
    """불법 도박·스포츠토토 및 과장 부업·재택알바 스팸 판별 (특수문자 우회 방어 포함)"""
    if not text:
        return False
    clean = re.sub(r'\s+', ' ', text)
    squashed = re.sub(r'[^가-힣a-zA-Z0-9]', '', clean)
    for target in (clean, squashed):
        if any(re.search(pat, target, re.IGNORECASE) for pat in LINKLESS_SPAM_PATTERNS):
            return True
    return False


def _is_safe_card_receipt(text: str) -> bool:
    """URL·회신번호·사칭유도어가 없는 순수 카드결제/입출금 알림 오탐 방지"""
    if not text:
        return False
    if CALLBACK_PHONE_PATTERN.search(text):
        return False
    squashed = re.sub(r'[^가-힣a-zA-Z]', '', text)
    if any(w in squashed for w in SCAM_ACTION_WORDS):
        return False
    return bool(NORMAL_CARD_ALERT_PATTERN.search(text))


def decide(ml_prob: float, has_url: bool, url_score: float, details: list, text: str = "") -> dict:
    st = link_status(has_url, url_score, details)
    if st == 'dangerous':
        v, b, d = '위험', 'URL', 'URL 위험 요인이 뚜렷함 (즉시 삭제 및 링크 클릭 금지)'
    elif st == 'suspicious':
        if ml_prob >= TH_MID:
            v, b, d = '위험', 'URL+문구', '의심스러운 링크와 스미싱 유사 문구가 함께 발견됨 (링크 클릭 금지)'
        else:
            v, b, d = '주의', 'URL', '목적지를 확인할 수 없거나 의심 요인이 있는 링크 포함'
    elif st == 'official':
        if _is_linkless_spam(text):
            v, b, d = '주의', '문구', '메신저·공식 링크가 포함되었으나 불법 도박·사행성 스팸 문구가 감지됨 (주의)'
        else:
            v, b, d = '안전', 'URL', '링크가 공식 도메인으로 확인됨'
    elif st == 'verified':
        if ml_prob >= TH_VERY_HIGH:
            v, b, d = '주의', 'URL+문구', '링크는 안전으로 확인됐으나 문구가 스미싱과 매우 유사하여 참고용 주의'
        else:
            v, b, d = '안전', 'URL', '링크가 공식 도메인이거나 안전 검증을 통과함'
    elif st == 'unverified':
        if ml_prob >= TH_VERY_HIGH:
            v, b, d = '위험', 'URL+문구', '확인되지 않은 링크와 스미싱 유사 문구가 강하게 결합됨'
        elif ml_prob >= TH_MID:
            v, b, d = '주의', '문구', '확인되지 않은 링크 포함, 문구에 의심 요소 있음'
        else:
            v, b, d = '안전', 'URL', '링크는 공식 확인되지 않았으나 뚜렷한 위험 요인은 없음'
    else:  # none: 링크 없음 → 문구만으로는 '위험' 금지, '주의'까지만 판정
        if _is_safe_card_receipt(text):
            v, b, d = '안전', '문구', '회신 번호나 링크가 없는 정상 금융 결제·입출금 알림으로 확인됨'
        elif _is_linkless_smishing(text, ml_prob):
            v, b, d = '주의', '문구', '링크가 없는 문자이나 지인·기관 사칭 또는 금전·연락 유도 정황이 감지됨 (주의)'
        elif _is_linkless_spam(text):
            v, b, d = '주의', '문구', '링크가 없는 문자이나 불법 도박 또는 과장 부업·재택알바 스팸이 감지됨 (주의)'
        else:
            v, b, d = '안전', '문구', '링크가 없어 URL 검사 없이 문구만 분석했습니다 (참고용)'
    return {'verdict': v, 'verdict_basis': b, 'verdict_detail': d, 'link_status': st}