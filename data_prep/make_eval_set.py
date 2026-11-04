# -*- coding: utf-8 -*-
"""
직접 작성한 평가용 문자 세트(학습에 쓰지 않는다). 악성 도메인은 모두 가상이며 실제 접속 대상이 아니다.
라벨 0=정상 1=스팸 2=스미싱 / expected_verdict = 시스템이 내야 할 기대 판정(안전 / 주의이상 / 위험)
 - 링크 있는 스미싱 → 위험, 링크 없는 사칭·스팸 → 주의이상, 정상 → 안전
실행: python make_eval_set.py --train dataset_v3.csv --out .   (학습 데이터와 겹치는 문장이 없는지도 검사)
"""
import argparse, os, re
import pandas as pd
from build_dataset import group_key

E = []  # (라벨, 분류, 문장)
def add(lab, cat, *msgs):
    for m in msgs: E.append((lab, cat, m))

# ---------- 정상(0): 공식 링크 포함 ----------
add(0, '정상-공식링크',
 "[Web발신] [한진택배] 고객님의 상품이 내일 배송될 예정입니다. 배송조회 https://www.hanjin.com",
 "[CJ대한통운] 택배가 오늘 오후 배송됩니다. 실시간 위치 확인 https://www.cjlogistics.com",
 "[11번가] 주문하신 상품이 발송되었습니다. 배송 현황은 https://www.11st.co.kr 에서 확인하세요.",
 "[무신사] 결제가 완료되었습니다. 주문내역은 https://www.musinsa.com/order 에서 볼 수 있어요.",
 "[국세청] 종합소득세 신고 안내입니다. 홈택스 https://www.hometax.go.kr 에서 신고하세요.",
 "[국민건강보험공단] 건강검진 대상자 안내. 검진기관 조회는 https://www.nhis.or.kr 에서 가능합니다.",
 "[쿠팡] 주문하신 상품이 오늘 도착 예정입니다. 자세한 내용은 https://www.coupang.com 에서 확인하세요.",
 "[올리브영] 주문하신 상품이 배송 완료되었습니다. 리뷰 작성 https://www.oliveyoung.co.kr",
 "[우체국] 소포가 오늘 배달 예정입니다. 배달조회: https://service.epost.go.kr",
 "[삼성카드] 10월 이용대금 명세서가 발송되었습니다. 상세 내역은 https://www.samsungcard.com 에서 확인하세요.",
 "[코레일] 승차권이 발권되었습니다. 열차 시간 변경은 https://www.letskorail.com 에서 가능합니다.",
 "[정부24] 신청하신 민원이 처리되었습니다. 결과 확인 https://www.gov.kr",
 "[토스] 송금이 완료되었어요. 내역은 https://toss.im 에서 확인하세요.",
 "[마켓컬리] 샛별배송 상품이 문 앞에 도착했어요. 주문 상세 https://www.kurly.com",
 "[네이버] 새로운 환경에서 로그인되었습니다. 본인이 아니라면 https://nid.naver.com 에서 확인하세요.")
# ---------- 정상(0): 링크 없음 ----------
add(0, '정상-인증번호',
 "[Web발신] [국민은행] 인증번호 [731904]를 입력해 주세요. 타인에게 절대 알려주지 마세요.",
 "[카카오뱅크] 본인확인 인증번호는 508217 입니다. 3분 안에 입력해 주세요.",
 "[하나카드] 온라인 결제 인증번호 220481, 본인이 아니면 카드 고객센터로 연락 바랍니다.",
 "[삼성페이] 인증번호 940127 을 입력해주세요.")
add(0, '정상-카드입금',
 "[Web발신] [신한카드] 승인 15,000원 일시불 스타벅스",
 "현대카드 3921승인 박OO님 84,300원 일시불 10/28 이마트",
 "[우리은행] 10/29 14:22 입금 1,200,000원 잔액 2,031,500원 급여",
 "[농협은행] 10/30 출금 50,000원 ATM 잔액 482,100원",
 "[롯데카드] 11월 결제 예정 금액 312,400원 안내. 결제일 25일입니다.")
add(0, '정상-일상대화',
 "내일 저녁 7시에 강남역에서 보자 늦지 마",
 "엄마 오늘 저녁은 밖에서 먹고 들어갈게요",
 "아빠 주말에 낚시 가시는 거 맞아요? 저도 같이 갈래요",
 "형 오늘 회식이라 늦을 것 같아 먼저 자",
 "누나 생일 축하해! 저녁에 케이크 사갈게")
add(0, '정상-공지예약',
 "[서울치과] 홍길동님 11/3 15:30 진료 예약이 확정되었습니다. 10분 전까지 접수해 주세요.",
 "[관리사무소] 내일 오전 10시 단지 내 소방점검이 있습니다. 세대 방문 예정이니 협조 부탁드립니다.",
 "[학원] 오늘 영어 수업은 강사 사정으로 휴강입니다. 보강일은 추후 안내드리겠습니다.")
# ---------- 스팸(1): 주의 이상 ----------
add(1, '스팸-도박',
 "(광고) 신규가입 첫충 100% 보너스 지급 카지노 슬롯 www.vip-bet88.com 무료거부 0808001234",
 "★토토 총판 모집★ 하루 수익 보장 입플 이벤트 진행중 bet-roll7.xyz",
 "[VIP]라이브 바카라 오늘만 10만원 꽁머니 지급 카톡 bj8888",
 "스포츠 분석 공유방 초대 무료픽 제공 t.me/sportspick77")
add(1, '스팸-구인광고',
 "(광고) 일당 25만원 당일지급 단순 사무보조 직원 모집 문의 카톡 job2024 무료거부 0801112222",
 "(광고) 월변 당일 대출 신용불량 가능 한도 500 전화주세요 010-4455-7788 무료거부 0809998888")
add(1, '스팸-투자',
 "주식 리딩방 무료 입장 수익률 300% 인증 오픈채팅 링크 bit.ly/stock-room1",
 "코인 선물 확정 수익 공유 지금 입장하세요 카톡 ID: coinlead99")
# ---------- 스미싱(2): 링크 있음 → 위험 ----------
add(2, '스미싱-택배',
 "[Web발신] [CJ대한통운] 고객님의 택배가 주소 오류로 반송 처리되었습니다. 주소 수정: https://cjlogis-kr.top/re",
 "[우체국택배] 부재중으로 배송하지 못했습니다. 재배송 신청 http://epost-delivery.xyz/12",
 "[한진택배] 배송 불가 지역으로 확인됩니다. 배송지 변경 https://hanjin-track.cc/addr",
 "[롯데택배] 고객님 택배가 분실되었습니다. 보상 신청 http://lotte-claim.top/a1",
 "[쿠팡] 배송 주소가 확인되지 않아 보류 중입니다. 확인 http://coupang-delivery.online/c")
add(2, '스미싱-단축URL',
 "[Web발신] 택배 도착 안내 확인하세요 bit.ly/3xYzQ12",
 "[국제발송] 해외 직구 상품 통관 보류 안내 http://me2.do/x8Kq1",
 "고객님 앞으로 중요 문서가 도착했습니다 https://han.gl/aQ7Zp",
 "[안내] 미수령 택배 확인 vo.la/Wm5dX")
add(2, '스미싱-금융사칭',
 "[국민은행] 해외 로그인 차단 안내. 본인 확인 후 해제하세요 https://kbstar-secure.xyz",
 "[신한카드] 비정상 결제 승인 1,290,000원 발생. 본인이 아니면 즉시 확인 http://shinhancard-check.top",
 "[카카오뱅크] 계정 보호를 위해 이용이 제한되었습니다. 인증 진행 https://kakaobank-verify.site",
 "[토스] 계좌가 일시 정지되었습니다. 본인인증 http://toss-auth.cc/v",
 "[농협] 보안카드 만료 안내. 재등록하지 않으면 거래가 중지됩니다 https://nonghyup-renew.top")
add(2, '스미싱-기관사칭',
 "[건강검진] 2026년 건강검진 통지서가 발송되었습니다. 내용 확인 https://nhis-notice.xyz/r",
 "[경찰청] 교통 범칙금 미납 안내. 납부 및 이의신청 http://efine-police.top/pay",
 "[국민연금] 연금 환급금 지급 대상자입니다. 조회 https://nps-refund.site",
 "[질병관리청] 예방접종 증명서 발급 및 본인확인 https://kdca-certify.cc",
 "[법원] 전자소송 송달문서가 도착했습니다. 확인 http://scourt-notice.top/m",
 "[국세청] 환급금 12만원이 미지급 상태입니다. 계좌 등록 https://nts-refund.online")
add(2, '스미싱-APK',
 "모바일 청첩장이 도착했습니다. 열어보기 http://wedding-card.top/invite.apk",
 "[부고] 故 이OO님 별세. 장례식장 안내 http://bugo-notice.xyz/view.apk",
 "[보안] 개인정보 유출 방지 앱을 설치해 주세요 https://safe-guard.cc/app.apk",
 "택배 확인 전용 앱 설치 후 조회 가능합니다 http://parcel-check.top/pc.apk")
add(2, '스미싱-지원금대출',
 "[정부지원] 소상공인 긴급 대출 승인 완료. 한도 확인 https://sbiz-loan.top/ok",
 "[서민금융] 최저금리 대환대출 사전승인 안내 http://lowrate-loan.xyz/apply",
 "[재난지원금] 지급 대상자로 선정되었습니다. 신청 https://support-fund.site/in")
# ---------- 스미싱(2): 링크 없음 → 주의 이상 ----------
add(2, '스미싱-링크없음',
 "엄마 나 폰 떨어뜨려서 액정 박살났어. 지금 수리 맡기고 친구 폰으로 문자해. 급하게 부탁할 게 있어",
 "아빠 나 휴대폰 고장나서 임시 번호야. 문화상품권 좀 사서 핀번호 보내줄 수 있어?",
 "이모 저 조카예요. 폰 바꿔서 연락드려요. 급한 결제가 있는데 대신 송금 가능하세요?",
 "[검찰청] 귀하 명의 계좌가 범죄에 연루되었습니다. 담당 수사관 02-5550-1234로 즉시 연락하세요.",
 "[국제발신] 해외승인 USD 1,299.00 AMAZON 본인 아닐 시 즉시 소비자보호센터 02-7012-3344 문의",
 "[Web발신] 주문하신 노트북 승인완료 1,890,000원. 취소 문의 02-3141-5566")

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--train', required=True); ap.add_argument('--out', default='.')
    a = ap.parse_args()
    d = pd.DataFrame(E, columns=['label', 'category', 'content'])
    d['label_name'] = d.label.map({0: '정상', 1: '스팸', 2: '스미싱'})
    d['has_url'] = d.content.str.contains(r'https?://|www\.|\b[a-z0-9\-]+\.(?:com|net|kr|do|gl|la|ly|xyz|top|cc|site|online|me)\b|t\.me/', case=False)
    d['expected_verdict'] = d.apply(lambda r: '안전' if r.label == 0 else ('위험' if (r.label == 2 and r.has_url) else '주의이상'), axis=1)
    d.insert(0, 'id', range(1, len(d) + 1))
    tr = pd.read_csv(a.train, encoding='utf-8-sig'); keys = set(tr.group)
    leak = d[d.content.map(group_key).isin(keys)]
    print(f'평가셋 {len(d)}건:', d.label_name.value_counts().to_dict(), '| 기대판정:', d.expected_verdict.value_counts().to_dict())
    print(f'학습 데이터와 겹침: {len(leak)}건' + (' ← 제거 필요' if len(leak) else ' (없음)'))
    d = d[~d.content.map(group_key).isin(keys)]
    d.to_csv(os.path.join(a.out, 'eval_set.csv'), index=False, encoding='utf-8-sig')

if __name__ == '__main__':
    main()
