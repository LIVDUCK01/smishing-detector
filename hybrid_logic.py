# -*- coding: utf-8 -*-
"""
계층형(URL 우선 + 사칭 도메인 + 무링크 사칭·스팸 및 특수문자 우회 방어) 판정 로직.
main_hybrid.py 와 evaluate.py 가 같은 함수를 쓰므로 서버와 평가 결과가 어긋나지 않는다.

원칙
  1) 링크가 있으면 URL 근거로 판정하고, 문구(ML) 점수는 '올리기만' 하는 보조 신호로 쓴다.
  2) 링크가 '공식 도메인'이면 문구 점수와 상관없이 '안전'. (단, 메신저 초대 링크에 불법 도박 스팸이 결합되면 '주의')
     VirusTotal만으로 깨끗하다고 확인된 링크는 문구가 매우 높을 때(85% 이상) '주의'까지만 올린다.
  3) 링크가 없으면 문구만으로는 '위험'을 내지 않고 '주의'까지만 낸다.
  4) 공식 사이트의 브랜드명을 비공식 도메인에 넣었으면 '사칭 도메인'으로 판정한다.
  5) 링크가 없어도 '메신저 ID 유도+금전 보상', '가족 사칭+번호 변경·금전 요구', '기관 사칭+전화 유도·위협',
     '불법 도박·과장 부업 스팸' 패턴이 있으면 특수문자 우회를 제거한 뒤에도 '주의'로 판정한다.
  6) 링크·회신번호·사칭 유도어가 없는 순수 카드 결제·입출금 알림 형식은 문구 점수와 무관하게 '안전'.
임계값(TH_*, URL_*)은 사전에 정한 초안이며, 평가셋 결과를 보고 사후에 맞춰 조정한 값이 아니다.
"""
import re
from urllib.parse import urlparse
from official_domains import OFFICIAL, OFFICIAL_SUFFIX, is_official_url, is_shortener_url

TH_HIGH, TH_MID, TH_VERY_HIGH = 70, 35, 85      # 문구(ML) 점수 기준 (%)
URL_DANGER, URL_SUSPECT = 50, 20                 # URL 위험도 점수 기준

# 정상 메신저 초대 도메인 (단축 URL 오탐 방지)
MESSENGER_DOMAINS = ('t.me', 'open.kakao.com')

# ───────────────────── 사칭 도메인 ─────────────────────
_GENERIC = {'gov', 'post', 'kt', 'ssg', 'ibk', 'auction'}
BRAND_TOKENS = {d.split('.')[0] for d in OFFICIAL if len(d.split('.')[0]) >= 3} - _GENERIC
BRAND_TOKENS |= {'efine', 'scourt', 'nts', 'police', 'hometax', 'minwon'}


def _is_messenger_url(url: str) -> bool:
    if not url:
        return False
    u = url if url.startswith(('http://', 'https://')) else 'http://' + url
    host = (urlparse(u).hostname or '').lower()
    return any(host == m or host.endswith('.' + m) for m in MESSENGER_DOMAINS)


def _is_real_official_host(host: str) -> bool:
    return (
        _is_messenger_url(host)
        or bool(re.fullmatch(r'(?:www\.)?[a-z0-9\-]+\.ac\.kr', host))
        or any(host == n or host.endswith('.' + n) for n in OFFICIAL)
        or any(host.endswith(s) for s in OFFICIAL_SUFFIX)
    )


def _impersonated_brand(host: str):
    for part in re.split(r'[.\-_]', host):
        if part in BRAND_TOKENS:
            return part
    return None


def impersonated_brand(details: list):
    for d in details:
        for u in (d.get('final_url'), d.get('original_url')):
            host = (urlparse(u).hostname or '').lower() if u else ''
            if not host or is_shortener_url(u) or _is_real_official_host(host):
                continue
            b = _impersonated_brand(host)
            if b:
                return b
    return None


# ───────────────────── 링크 없는 문구 패턴 (특수문자 우회 방어 포함) ─────────────────────
_MESSENGER = re.compile(
    r'(?:카톡|카카오톡|오픈채팅|텔레그램|텔그|위챗|kakao|kakaotalk|telegram)\s*(?:ID|아이디)?\s*[:：]?\s*'
    r'(?:@[a-z0-9_]{4,}|(?=[a-z_]*\d)[a-z0-9_]{4,})',
    re.I
)
_REWARD = re.compile(r'지급|수당|일급|보너스|수익|꽁머니|충전|환급|지원금|대출|투자|입금|배당|당첨|\d+\s*만\s*원')
_FAMILY = re.compile(r'(?<![가-힣])(?:엄마|아빠|어머니|아버지|이모|삼촌|고모|할머니|할아버지|아들|딸|누나|언니|형|오빠|조카)')
_PHONE_CHANGE = re.compile(r'(?:폰|핸드폰|휴대폰|번호).{0,12}?(?:고장|바꿨|바꿔|분실|수리|액정|깨져|교체|임시\s*폰)')
_MONEY = re.compile(r'송금|입금|이체|결제|기프트\s*카드|문화\s*상품권|상품권|핀\s*번호|계좌|원격\s*제어|팀뷰어|\d+\s*만\s*원')
_AGENCY = re.compile(r'검찰|지검|검사|수사관|경찰|금융감독원|금감원|법원|국세청|금융위|대검')
_PHONE_NO = re.compile(r'(?:010|070|050\d?|02|03[1-3]|04[1-4]|05[1-5]|06[1-4]|1[568]\d{2})[-\s]?\d{3,4}[-\s]?\d{4}')
_THREAT = re.compile(r'사건|연루|범죄|대포통장|명의\s*도용|계좌\s*(?:보호|동결|정지|지급정지)|유출|압수|체포|소환|출석|피해자|수배|구속|영장|신고\s*접수')

# 불법 도박·사행성 및 과장 부업·재택알바 스팸 (리딩방·투자권유 제외 유지)
_GAMBLING_SPAM = re.compile(
    r'바카라|카지노|꽁머니|사설\s*토토|파워볼|첫충|매충|환전\s*보장|보증\s*업체|'
    r'스포츠\s*분석|무료\s*픽|유료\s*픽|픽스터|배당률|프로토\s*분석'
)
_JOB_SPAM = re.compile(
    r'(?:재택\s*알바|재택\s*근무|부업\s*안내|리뷰\s*작성|단순\s*사무보조).*'
    r'(?:일급|일당|월\s*\d+만원|당일\s*지급|고수익|초보\s*가능|\d+만원)'
)

# 순수 카드 결제·입출금 알림 안전 예외 패턴 (사칭·수수료·해외승인·콜백번호 철저 배제)
_SAFE_RECEIPT = re.compile(
    r'(?:'
    r'(?:카드|체크|페이|승인).*(?:[\d,]+원\s*(?:일시불|할부|\d+\s*개월|승인)|(?:일시불|할부|\d+\s*개월)\s*[\d,]+원|승인.*[\d,]+원.*누적)'
    r'|(?:은행|뱅크|농협|신한|국민|우리|하나|기업|토스|카카오).*?(?:입금|출금)\s*[\d,]+원.*잔액'
    r'|결제\s*예정\s*금액\s*[\d,]+원'
    r')',
    re.I
)
_UNSAFE_RECEIPT_WORDS = re.compile(
    r'본인|아닐|아니면|확인|문의|연락|전화|클릭|링크|즉시|차단|도용|비정상|오류|보호|정지|'
    r'수수료|선입금|대출|연체|당첨|환급|미납|검찰|경찰|수사관|금감원|송금|이체\s*요청|'
    r'국외|해외\s*(?:결제|승인)|기프트|상품권|원격|계좌\s*번호|급하게|보내줘',
    re.I
)


def _normalize_texts(text: str) -> tuple:
    clean = re.sub(r'\s+', ' ', text)
    squashed = re.sub(r'[^가-힣a-zA-Z0-9]', '', clean)
    return clean, squashed


def _is_linkless_spam(text: str) -> bool:
    if not text:
        return False
    clean, squashed = _normalize_texts(text)
    return bool(
        _GAMBLING_SPAM.search(clean) or _GAMBLING_SPAM.search(squashed)
        or _JOB_SPAM.search(clean) or _JOB_SPAM.search(squashed)
    )


def text_signals(text: str) -> list:
    """링크 없는 문자에서 스미싱·스팸의 전형적 조합을 찾아 목록으로 반환 (특수문자 우회 방어 포함)"""
    if not text:
        return []
    clean, squashed = _normalize_texts(text)
    sig = []

    if (_MESSENGER.search(clean) or _MESSENGER.search(squashed)) and (_REWARD.search(clean) or _REWARD.search(squashed)):
        sig.append('메신저 ID 유도 + 금전·보상 문구')

    has_family = bool(_FAMILY.search(clean) or _FAMILY.search(squashed))
    has_phone_chg = bool(_PHONE_CHANGE.search(clean) or _PHONE_CHANGE.search(squashed))
    has_money = bool(_MONEY.search(clean) or _MONEY.search(squashed))
    if has_family and ((has_phone_chg and (has_money or '부탁' in squashed)) or ('급하게' in squashed and has_money)):
        sig.append('가족 사칭 + 번호 변경·금전 요구')

    has_agency = bool(_AGENCY.search(clean) or _AGENCY.search(squashed))
    has_phone = bool(_PHONE_NO.search(clean))
    has_threat = bool(_THREAT.search(clean) or _THREAT.search(squashed))
    if has_agency and (has_phone or has_threat):
        sig.append('기관 사칭 + 전화 유도·위협 표현')

    if _GAMBLING_SPAM.search(clean) or _GAMBLING_SPAM.search(squashed):
        sig.append('불법 도박·사행성 스팸 문구')

    if _JOB_SPAM.search(clean) or _JOB_SPAM.search(squashed):
        sig.append('과장 부업·재택알바 스팸 문구')

    return sig


def is_card_approval(text: str) -> bool:
    """URL·회신번호·사칭유도어가 없는 순수 카드결제/입출금 알림 여부"""
    if not text:
        return False
    if _PHONE_NO.search(text):
        return False
    _, squashed = _normalize_texts(text)
    if _UNSAFE_RECEIPT_WORDS.search(text) or _UNSAFE_RECEIPT_WORDS.search(squashed):
        return False
    return bool(_SAFE_RECEIPT.search(text))


# ───────────────────── 판정 ─────────────────────
def _item_official(d: dict) -> bool:
    """URL 1개가 공식 도메인인지 검증 (화이트리스트 + 메신저 공식 초대 링크 동기화)"""
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
        not _is_messenger_url(d.get('original_url', ''))
        and is_shortener_url(d.get('original_url', ''))
        and is_shortener_url(d.get('final_url') or d.get('original_url', ''))
        for d in details
    )
    if url_score >= URL_SUSPECT or unresolved:
        return 'suspicious'
    if details and all(_item_official(d) for d in details):
        return 'official'
    if details and url_score == 0 and all(_item_vt_clean(d) for d in details):
        return 'verified'
    return 'unverified'


def decide(ml_prob: float, has_url: bool, url_score: float, details: list, text: str = '') -> dict:
    """text 는 선택 인자(기존 호출과 호환)"""
    st = link_status(has_url, url_score, details)
    brand = impersonated_brand(details) if st not in ('none', 'dangerous', 'official') else None
    signals = []

    if st == 'dangerous':
        v, b, d = '위험', 'URL', 'URL 위험 요인이 뚜렷함 (즉시 삭제 및 링크 클릭 금지)'
    elif brand:
        st, signals = 'suspicious', [f'공식 사이트({brand}) 사칭 도메인']
        if url_score >= URL_SUSPECT or ml_prob >= TH_MID:
            v, b, d = '위험', ('URL+문구' if ml_prob >= TH_MID else 'URL'), f'공식 사이트({brand})를 흉내 낸 도메인에 의심 요소가 겹침 (링크 클릭 금지)'
        else:
            v, b, d = '주의', 'URL', f'공식 사이트({brand}) 이름을 쓰지만 공식 도메인이 아닙니다. 주소를 직접 확인하세요'
    elif st == 'suspicious':
        if ml_prob >= TH_HIGH:
            v, b, d = '위험', 'URL+문구', '의심스러운 링크와 스미싱 유사 문구가 함께 발견됨 (링크 클릭 금지)'
        else:
            v, b, d = '주의', 'URL', '목적지를 확인할 수 없거나 의심 요소가 있는 링크 포함'
    elif st == 'official':
        if _is_linkless_spam(text):
            signals = ['메신저·공식 링크 + 불법 도박·사행성 스팸 문구']
            v, b, d = '주의', '문구', '공식·메신저 링크가 포함되었으나 불법 도박·사행성 스팸 문구가 감지됨 (주의)'
        else:
            v, b, d = '안전', 'URL', '링크가 공식 도메인으로 확인됨'
    elif st == 'verified':
        if ml_prob >= TH_VERY_HIGH:
            v, b, d = '주의', 'URL+문구', '링크는 공식·안전으로 확인됐으나 문구가 스미싱과 매우 유사하여 참고용 주의'
        else:
            v, b, d = '안전', 'URL', '링크가 공식 도메인이거나 안전 검증을 통과함'
    elif st == 'unverified':
        if ml_prob >= TH_VERY_HIGH:
            v, b, d = '위험', 'URL+문구', '확인되지 않은 링크와 스미싱 유사 문구가 강하게 결합됨'
        elif ml_prob >= TH_MID:
            v, b, d = '주의', '문구', '확인되지 않은 링크 포함, 문구에 의심 요소 있음'
        else:
            v, b, d = '안전', 'URL', '링크는 공식 확인되지 않았으나 뚜렷한 위험 요인은 없음'
    else:  # none: 링크 없음 → 문구만으로는 '위험' 금지
        signals = text_signals(text)
        if signals:
            v, b, d = '주의', '문구', '링크는 없지만 ' + ', '.join(signals) + ' 패턴이 발견됨. 금전·개인정보 요구에 응하지 마세요 (참고용)'
        elif is_card_approval(text):
            v, b, d = '안전', '문구', '링크·요구 문구가 없는 정상 카드 결제·입출금 알림 형식입니다 (참고용)'
        elif ml_prob >= TH_HIGH:
            v, b, d = '주의', '문구', '링크가 없는 문자입니다. 문구가 스미싱과 유사하니 금전·개인정보 요구에 응하지 마세요 (참고용)'
        else:
            v, b, d = '안전', '문구', '링크가 없어 URL 검사 없이 문구만 분석했습니다 (참고용)'

    return {'verdict': v, 'verdict_basis': b, 'verdict_detail': d, 'link_status': st, 'signals': signals}
