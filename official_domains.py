# -*- coding: utf-8 -*-
"""
공식 도메인 / 사용자 콘텐츠 호스트 / 단축 URL 목록.
※ 목록은 일반적으로 알려진 공식 주소를 모은 초안이다. 팀에서 한 번 더 확인하고, 팀원이 합친 url_checker.py의
   TRUSTED_DOMAINS·SHORTENER_DOMAINS 가 확정되면 이 목록과 합칠 것.
"""
from urllib.parse import urlparse

OFFICIAL = [
    # 택배·우편
    'cjlogistics.com', 'hanjin.com', 'lotteglogis.com', 'ilogen.com', 'epost.go.kr', 'post.go.kr', 'cupost.co.kr', 'cvsnet.co.kr',
    # 쇼핑
    'coupang.com', '11st.co.kr', 'gmarket.co.kr', 'auction.co.kr', 'musinsa.com', 'kurly.com', 'oliveyoung.co.kr', 'ssg.com', 'lotteon.com',
    # 포털·메신저·간편결제
    'naver.com', 'kakao.com', 'daum.net', 'google.com', 'toss.im', 'daangn.com', 'kakaopay.com',
    # 은행·카드·증권
    'kbstar.com', 'shinhan.com', 'shinhancard.com', 'wooribank.com', 'hanabank.com', 'hanacard.co.kr', 'nonghyup.com', 'nhbank.com',
    'ibk.co.kr', 'kakaobank.com', 'tossbank.com', 'samsungcard.com', 'hyundaicard.com', 'lottecard.co.kr', 'kbcard.com', 'samsungpop.com',
    # 공공
    'gov.kr', 'nhis.or.kr', 'nps.or.kr', 'korail.com', 'letskorail.com', 'hipass.co.kr', 'kepco.co.kr',
    # 통신
    'tworld.co.kr', 'sktelecom.com', 'kt.com', 'uplus.co.kr', 'lguplus.com',
]
OFFICIAL_SUFFIX = ['.go.kr']        # 정부 기관(*.go.kr)은 통째로 신뢰

# 공식 도메인 아래에 있어도 '아무나 글·파일을 올릴 수 있는' 호스트 → 신뢰하지 않는다 (피싱 호스팅에 자주 악용)
USER_CONTENT = ['docs.google.com', 'sites.google.com', 'forms.gle', 'forms.google.com', 'drive.google.com', 'storage.googleapis.com',
                'open.kakao.com', 'blog.naver.com', 'cafe.naver.com', 'm.blog.naver.com', 'tistory.com']

SHORTENERS = ['bit.ly', 'me2.do', 'han.gl', 'vo.la', 'url.kr', 't.co', 'tinyurl.com', 'rb.gy', 'shorturl.at', 'ow.ly', 'goo.gl',
              'bitly.kr', 'lrl.kr', 'naver.me', 'is.gd', 'cutt.ly', 'buly.kr', 't.me']


def _host(url: str) -> str:
    try:
        return (urlparse(url if '://' in url else 'http://' + url).hostname or '').lower()
    except ValueError:
        return ''

def _match(host: str, names) -> bool:
    return any(host == n or host.endswith('.' + n) for n in names)

def is_official_url(url: str) -> bool:
    h = _host(url)
    if not h or _match(h, USER_CONTENT): return False
    return _match(h, OFFICIAL) or any(h.endswith(s) for s in OFFICIAL_SUFFIX)

def is_shortener_url(url: str) -> bool:
    return _match(_host(url), SHORTENERS)
