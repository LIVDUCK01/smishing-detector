# -*- coding: utf-8 -*-
"""
계층형(URL 우선) 판정 로직. main_hybrid.py 와 evaluate.py 가 같은 함수를 쓰므로 서버와 평가 결과가 어긋나지 않는다.

원칙
  1) 링크가 있으면 URL 근거로 판정하고, 문구(ML) 점수는 '올리기만' 하는 보조 신호로 쓴다.
  2) 링크가 '공식 도메인'이면 문구 점수와 상관없이 '안전'. (공식 도메인은 공격자가 쓸 수 없고, 사용자 콘텐츠 호스트는 목록에서 제외)
     VirusTotal만으로 깨끗하다고 확인된 링크는 문구가 매우 높을 때(85% 이상) '주의'까지만 올린다.
  3) 링크가 없으면 문구만으로는 '위험'을 내지 않고 '주의'까지만 낸다.
임계값은 사전에 정한 초안이며, 평가셋 결과를 보고 사후에 맞춰 조정한 값이 아니다.
"""
from official_domains import is_official_url, is_shortener_url

TH_HIGH, TH_MID, TH_VERY_HIGH = 70, 35, 85      # 문구(ML) 점수 기준 (%)
URL_DANGER, URL_SUSPECT = 50, 20                 # URL 위험도 점수 기준


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

def decide(ml_prob: float, has_url: bool, url_score: float, details: list) -> dict:
    st = link_status(has_url, url_score, details)
    if st == 'dangerous':
        v, b, d = '위험', 'URL', 'URL 위험 요인이 뚜렷함 (즉시 삭제 및 링크 클릭 금지)'
    elif st == 'suspicious':
        if ml_prob >= TH_HIGH: v, b, d = '위험', 'URL+문구', '의심스러운 링크와 스미싱 유사 문구가 함께 발견됨 (링크 클릭 금지)'
        else:                  v, b, d = '주의', 'URL', '목적지를 확인할 수 없거나 의심 요인이 있는 링크 포함'
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
        if ml_prob >= TH_HIGH: v, b, d = '주의', '문구', '링크가 없는 문자입니다. 문구가 스미싱과 유사하니 금전·개인정보 요구에 응하지 마세요 (참고용)'
        else:                  v, b, d = '안전', '문구', '링크가 없어 URL 검사 없이 문구만 분석했습니다 (참고용)'
    return {'verdict': v, 'verdict_basis': b, 'verdict_detail': d, 'link_status': st}
