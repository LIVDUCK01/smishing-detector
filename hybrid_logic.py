# -*- coding: utf-8 -*-
"""
계층형(URL 우선) 판정 로직. main_hybrid.py 와 evaluate.py 가 같은 함수를 쓰므로 서버와 평가 결과가 어긋나지 않는다.

원칙
  1) 링크가 있으면 URL 근거로 판정하고, 문구(ML) 점수는 '올리기만' 하는 보조 신호로 쓴다.
  2) 링크가 '공식 도메인'이면 문구 점수와 상관없이 '안전'. (공식 도메인은 공격자가 쓸 수 없고, 사용자 콘텐츠 호스트는 목록에서 제외)
     VirusTotal만으로 깨끗하다고 확인된 링크는 문구가 매우 높을 때(85% 이상) '주의'까지만 올린다.
  3) 링크가 없으면 문구만으로는 '위험'을 내지 않고 '주의'까지만 낸다.
  4) [추가] 공식 사이트의 이름(브랜드)을 도메인에 넣었지만 공식 도메인이 아니면 '사칭 도메인'으로 본다.
     공격자는 공식 도메인을 쓸 수 없으므로 이 신호는 임계값 조정 없이 성립한다. 사칭 도메인은 최소 '주의',
     의심 TLD 등 URL 의심 요소 또는 문구 점수(TH_MID 이상)가 하나라도 겹치면 '위험'.
  5) [추가] 링크가 없어도 '연락처 유도+금전 보상', '가족 사칭+번호 변경+금전 요구', '기관 사칭+전화번호+위협 표현'
     처럼 스미싱·보이스피싱의 전형적 조합이 문구에 있으면 '주의'. (위험은 내지 않음 — 원칙 3 유지)
  6) [추가] 링크 없는 카드 승인 알림 형식(요구·유도 문구 없음)은 문구 점수와 무관하게 '안전'.
임계값(TH_*, URL_*)은 사전에 정한 초안이며, 평가셋 결과를 보고 사후에 맞춰 조정한 값이 아니다. (이번 수정에서도 변경 없음)
"""
import re
from urllib.parse import urlparse
from official_domains import OFFICIAL, OFFICIAL_SUFFIX, is_official_url, is_shortener_url

TH_HIGH, TH_MID, TH_VERY_HIGH = 70, 35, 85      # 문구(ML) 점수 기준 (%)
URL_DANGER, URL_SUSPECT = 50, 20                 # URL 위험도 점수 기준

# ───────────────────── 사칭 도메인 ─────────────────────
_GENERIC = {'gov', 'post', 'kt', 'ssg', 'ibk', 'auction'}                 # 너무 일반적인 이름은 브랜드로 보지 않음
BRAND_TOKENS = {d.split('.')[0] for d in OFFICIAL if len(d.split('.')[0]) >= 3} - _GENERIC
# *.go.kr 은 공식 목록에 접미사로만 있어 이름을 뽑을 수 없으므로, 자주 사칭되는 기관명을 따로 둔다 (팀에서 보강할 것)
BRAND_TOKENS |= {'efine', 'scourt', 'nts', 'police', 'hometax', 'minwon'}


def _is_real_official_host(host: str) -> bool:
    """사용자 콘텐츠 호스트(blog.naver.com 등)도 '진짜 공식 도메인 아래'이면 사칭이 아니다."""
    return any(host == n or host.endswith('.' + n) for n in OFFICIAL) or any(host.endswith(s) for s in OFFICIAL_SUFFIX)


def _impersonated_brand(host: str):
    """도메인을 . - _ 로 나눈 조각 중 브랜드 이름과 정확히 같은 것이 있으면 그 브랜드를 반환 (붙여 쓴 이름은 잡지 않음 → 오탐 방지)"""
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


# ───────────────────── 링크 없는 문구 패턴 ─────────────────────
_MESSENGER = re.compile(r'(?:카톡|카카오톡|오픈채팅|텔레그램|텔그|위챗|kakao|kakaotalk|telegram)\s*(?:ID|아이디)?\s*[:：]?\s*'
                        r'(?:@[a-z0-9_]{4,}|(?=[a-z_]*\d)[a-z0-9_]{4,})', re.I)          # 카톡 ID 형태(숫자 포함 또는 @아이디)
_REWARD = re.compile(r'지급|수당|일급|보너스|수익|꽁머니|충전|환급|지원금|대출|투자|입금|배당|당첨|\d+\s*만\s*원')
_FAMILY = re.compile(r'(?<![가-힣])(?:엄마|아빠|어머니|아버지|이모|삼촌|고모|할머니|할아버지|아들|딸|누나|언니|형|오빠|조카)')
_PHONE_CHANGE = re.compile(r'(?:폰|핸드폰|휴대폰|번호).{0,8}?(?:고장|바꿨|바꿔|분실|수리|액정|깨져|교체)')
_MONEY = re.compile(r'송금|입금|이체|결제|기프트\s*카드|상품권|핀\s*번호|계좌|\d+\s*만\s*원')
_AGENCY = re.compile(r'검찰|지검|검사|수사관|경찰|금융감독원|금감원|법원|국세청|금융위|대검')
_PHONE_NO = re.compile(r'0\d{1,2}-\d{3,4}-\d{4}|1[5-9]\d{2}-\d{4}')
_THREAT = re.compile(r'사건|연루|범죄|대포통장|명의\s*도용|계좌\s*(?:보호|동결|정지|지급정지)|유출|압수|체포|소환|출석|피해자|수배')
_CARD_APPROVAL = re.compile(r'^\s*(?:\[Web발신\]\s*)?\[[^\]]*(?:카드|은행)[^\]]*\]\s*(?:해외\s*)?승인\s*[\d,]+원\s*(?:일시불|\d+\s*개월)', re.I)
_ASKING = re.compile(r'본인|아니|확인|문의|연락|전화|클릭|링크|즉시|차단|도용|비정상|오류|보호|정지')


def text_signals(text: str) -> list:
    """링크 없는 문자에서 스미싱·보이스피싱의 전형적 조합을 찾아 이름 목록으로 반환"""
    if not text:
        return []
    sig = []
    if _MESSENGER.search(text) and _REWARD.search(text):
        sig.append('메신저 ID 유도 + 금전·보상 문구')
    if _FAMILY.search(text) and _PHONE_CHANGE.search(text) and _MONEY.search(text):
        sig.append('가족 사칭 + 번호 변경 + 금전 요구')
    if _AGENCY.search(text) and _PHONE_NO.search(text) and _THREAT.search(text):
        sig.append('기관 사칭 + 전화 연락 유도 + 위협 표현')
    return sig


def is_card_approval(text: str) -> bool:
    return bool(text) and bool(_CARD_APPROVAL.search(text)) and not _ASKING.search(text)


# ───────────────────── 판정 ─────────────────────
def _item_official(d: dict) -> bool:
    """URL 1개가 공식 도메인인지. 단축 URL은 '최종 목적지'가 공식 도메인일 때만 인정."""
    orig, final = d.get('original_url', ''), d.get('final_url') or d.get('original_url', '')
    if is_shortener_url(orig):
        return (not is_shortener_url(final)) and is_official_url(final)
    return is_official_url(orig) and is_official_url(final)

def _item_vt_clean(d: dict) -> bool:
    vt = d.get('virustotal')
    return vt is not None and vt.get('malicious', 1) == 0 and vt.get('suspicious', 1) == 0

def link_status(has_url: bool, url_score: float, details: list) -> str:
    """none / dangerous / suspicious / official / verified(VirusTotal) / unverified"""
    if not has_url: return 'none'
    if url_score >= URL_DANGER: return 'dangerous'
    unresolved = any(is_shortener_url(d.get('original_url', '')) and is_shortener_url(d.get('final_url') or d.get('original_url', '')) for d in details)
    if url_score >= URL_SUSPECT or unresolved: return 'suspicious'     # 목적지를 알 수 없는 단축 URL 포함
    if details and all(_item_official(d) for d in details): return 'official'
    if details and url_score == 0 and all(_item_vt_clean(d) for d in details): return 'verified'
    return 'unverified'

def decide(ml_prob: float, has_url: bool, url_score: float, details: list, text: str = '') -> dict:
    """text 는 선택 인자(없으면 링크 없는 문구 패턴 규칙만 건너뜀 → 기존 호출과 호환)"""
    st = link_status(has_url, url_score, details)
    brand = impersonated_brand(details) if st not in ('none', 'dangerous', 'official') else None
    signals = []
    if st == 'dangerous':
        v, b, d = '위험', 'URL', 'URL 위험 요인이 뚜렷함 (즉시 삭제 및 링크 클릭 금지)'
    elif brand:                 # 공식 사이트 이름을 흉내 낸 비공식 도메인
        st, signals = 'suspicious', [f'공식 사이트({brand}) 사칭 도메인']
        if url_score >= URL_SUSPECT or ml_prob >= TH_MID:
            v, b, d = '위험', ('URL+문구' if ml_prob >= TH_MID else 'URL'), f'공식 사이트({brand})를 흉내 낸 도메인에 의심 요소가 겹침 (링크 클릭 금지)'
        else:
            v, b, d = '주의', 'URL', f'공식 사이트({brand}) 이름을 쓰지만 공식 도메인이 아닙니다. 주소를 직접 확인하세요'
    elif st == 'suspicious':
        if ml_prob >= TH_HIGH: v, b, d = '위험', 'URL+문구', '의심스러운 링크와 스미싱 유사 문구가 함께 발견됨 (링크 클릭 금지)'
        else:                  v, b, d = '주의', 'URL', '목적지를 확인할 수 없거나 의심 요소가 있는 링크 포함'
    elif st == 'official':      # 공식 도메인: 문구 점수와 무관하게 안전
        v, b, d = '안전', 'URL', '링크가 공식 도메인으로 확인됨'
    elif st == 'verified':      # VirusTotal 로만 확인된 링크
        if ml_prob >= TH_VERY_HIGH: v, b, d = '주의', 'URL+문구', '링크는 공식·안전으로 확인됐으나 문구가 스미싱과 매우 유사하여 참고용 주의'
        else:                       v, b, d = '안전', 'URL', '링크가 공식 도메인이거나 안전 검증을 통과함'
    elif st == 'unverified':
        if ml_prob >= TH_VERY_HIGH: v, b, d = '위험', 'URL+문구', '확인되지 않은 링크와 스미싱 유사 문구가 강하게 결합됨'
        elif ml_prob >= TH_MID:     v, b, d = '주의', '문구', '확인되지 않은 링크 포함, 문구에 의심 요소 있음'
        else:                       v, b, d = '안전', 'URL', '링크는 공식 확인되지 않았으나 뚜렷한 위험 요인은 없음'
    else:  # none: 링크 없음 → 문구만으로는 '위험' 금지
        signals = text_signals(text)
        if signals:
            v, b, d = '주의', '문구', '링크는 없지만 ' + ', '.join(signals) + ' 패턴이 발견됨. 금전·개인정보 요구에 응하지 마세요 (참고용)'
        elif ml_prob >= TH_HIGH and is_card_approval(text):
            v, b, d = '안전', '문구', '링크·요구 문구가 없는 카드 승인 알림 형식입니다 (참고용)'
        elif ml_prob >= TH_HIGH:
            v, b, d = '주의', '문구', '링크가 없는 문자입니다. 문구가 스미싱과 유사하니 금전·개인정보 요구에 응하지 마세요 (참고용)'
        else:
            v, b, d = '안전', '문구', '링크가 없어 URL 검사 없이 문구만 분석했습니다 (참고용)'
    return {'verdict': v, 'verdict_basis': b, 'verdict_detail': d, 'link_status': st, 'signals': signals}
