# -*- coding: utf-8 -*-
"""
정상 문자형 알림(택배·인증번호·카드 승인·입출금·공공기관·통신사·예약·가족 대화 등)을 직접 작성한 템플릿으로 만든다.
 - 템플릿 약 100개 × 변형 2~3개. 같은 템플릿은 3개까지만 만들어 '템플릿 반복' 문제를 피한다.
 - 합성 데이터이므로 source='synthetic_normal' 로 표시하고, 전부 train 에만 넣는다(평가에는 사용 금지).
 - 보고서에는 '직접 작성한 합성 정상 문자 포함'이라고 명시할 것.
실행: python make_synthetic_normal.py --base dataset_v2_final.csv --out .   → synthetic_normal.csv, dataset_v3.csv
"""
import argparse, os, random, re
import pandas as pd
from build_dataset import group_key

R = random.Random(7)
pick = lambda xs: R.choice(xs)
def amt(lo=1500, hi=89000): return f"{R.randrange(lo, hi, 100):,}"
def bal(): return f"{R.randrange(12000, 3800000, 10):,}"
def otp(n=6): return ''.join(R.choice('0123456789') for _ in range(n))
def md(): return f"{R.randint(1, 12)}/{R.randint(1, 28)}"
def tm(): return f"{R.randint(9, 21)}:{pick(['00', '10', '20', '30', '40', '50'])}"
def tmr(): h = R.randint(9, 19); return f"{h}시~{h + 2}시"
def day(): return pick(['월요일', '화요일', '수요일', '목요일', '금요일', '토요일', '일요일'])
def ym(): return f"{R.randint(1, 12)}월"
def pay(): return pick([5, 10, 15, 20, 25])
def name(): return pick(['김민수', '이서연', '박지훈', '최유진', '정하늘', '강도윤', '조서윤', '윤재민', '장예린', '한지우'])
def inv(): return otp(12)
def l4(): return otp(4)

COURIERS = ['CJ대한통운', '한진택배', '롯데택배', '우체국택배', '로젠택배']
SHOPS = {'쿠팡': 'coupang.com', '11번가': '11st.co.kr', '무신사': 'musinsa.com', '마켓컬리': 'kurly.com', '올리브영': 'oliveyoung.co.kr', 'G마켓': 'gmarket.co.kr'}
ITEMS = ['무선 이어폰', '텀블러', '운동화', '노트북 파우치', '생수 2L 12병', '책 3권', '샴푸 세트', '후드티', '전기포트', '키보드', '양말 5족', '비타민']
BANKS = ['국민은행', '신한은행', '우리은행', '하나은행', '농협은행', '카카오뱅크', '토스뱅크', '기업은행']
CARDS = ['신한카드', '삼성카드', '현대카드', 'KB국민카드', '롯데카드', '하나카드', '우리카드']
STORES = ['스타벅스', 'GS25', 'CU', '이마트', '다이소', '교보문고', '올리브영', '메가커피', '맥도날드', '쿠팡이츠']
TELCOS = ['SKT', 'KT', 'LGU+']
SECS = ['삼성증권', '미래에셋증권', '키움증권', '한국투자증권']
STOCKS = ['삼성전자', '카카오', '네이버', 'LG에너지솔루션', '현대차']
HOSP = ['우리내과의원', '서울치과', '연세정형외과', '밝은안과', '새봄소아과']
CITY = ['수원', '화성', '성남', '부산', '대전', '광주', '인천']
SVC = ['네이버', '카카오', '쿠팡', '당근', '토스', '배달의민족']
shop = lambda: pick(list(SHOPS))

# (분류, 템플릿 함수) — 각 템플릿에서 변형을 최대 3개 만든다
T = []
def t(cat, fn, k=3): T.append((cat, fn, k))

# --- 택배/쇼핑 ---
t('택배', lambda: f"[{pick(COURIERS)}] {name()}님, 오늘 {tmr()} 사이 배송 예정입니다. 송장번호 {inv()}")
t('택배', lambda: f"[CJ대한통운] 고객님의 상품이 {tm()}에 배송 완료되었습니다. 문 앞에 두었습니다.")
t('택배', lambda: (lambda s: f"[{s}] 주문하신 '{pick(ITEMS)}' 상품이 출고되었습니다. 배송조회: https://www.{SHOPS[s]}/orders")(shop()))
t('택배', lambda: f"{pick(COURIERS)} 택배기사입니다. 오늘 {tmr()} 도착 예정이며 부재 시 경비실에 맡기겠습니다.")
t('택배', lambda: f"[한진택배] 고객님 상품이 {pick(CITY)} 터미널에 도착했습니다. 내일 배송 예정입니다.")
t('택배', lambda: f"[우체국] 등기우편물이 {tmr()}에 배달 예정입니다. 부재 시 우편함에 투함됩니다. 배송조회 https://service.epost.go.kr")
t('택배', lambda: f"[롯데택배] {name()}님 상품 배송출발! 오늘 {tmr()} 도착 예정이에요.")
t('택배', lambda: f"[{shop()}] 반품 요청이 접수되었습니다. 수거기사님이 {day()}에 방문 예정입니다.")
t('택배', lambda: f"[{shop()}] 배송이 완료되었습니다. 상품은 마음에 드셨나요? 리뷰를 남기시면 포인트를 드립니다.")
t('택배', lambda: f"택배함 보관 안내: {pick(ITEMS)} 택배가 무인택배함에 보관되었습니다. 비밀번호는 휴대폰 뒤 4자리입니다.")
t('택배', lambda: f"[{pick(COURIERS)}] 배송 지연 안내: 물량 증가로 배송이 하루 지연되고 있습니다. 불편을 드려 죄송합니다.")
t('택배', lambda: f"[쿠팡] 로켓배송 {pick(ITEMS)} 오늘 {tmr()} 도착 예정입니다. 문 앞에 놓아드릴게요.")
t('택배', lambda: f"[편의점택배] {pick(ITEMS)} 상품이 {pick(['GS25', 'CU', '세븐일레븐'])} 점포에 도착했습니다. 7일 이내 수령해주세요.")
t('택배', lambda: f"[{shop()}] 주문 취소가 완료되었습니다. 결제 금액 {amt()}원은 영업일 기준 3일 내 환불됩니다.")
# --- 인증번호 ---
t('인증', lambda: f"[{pick(BANKS)}] 인증번호 [{otp()}]를 입력해 주세요. 타인에게 절대 알려주지 마세요.")
t('인증', lambda: f"[네이버] 인증번호 {otp()}를 입력해주세요. 인증번호는 3분간 유효합니다.")
t('인증', lambda: f"[카카오톡] 인증번호 [{otp(4)}] 타인에게 알려주지 마세요.")
t('인증', lambda: f"[토스] 인증번호 {otp()} 를 입력해 주세요.")
t('인증', lambda: f"[{pick(TELCOS)}] 본인확인 인증번호는 [{otp()}]입니다. 정확히 입력해 주세요.")
t('인증', lambda: f"G-{otp()} is your Google verification code.")
t('인증', lambda: f"[당근] 인증번호 {otp(4)}를 입력해주세요. 타인에게 알려주지 마세요.")
t('인증', lambda: f"[정부24] 본인인증 번호는 {otp()}입니다. 5분 이내에 입력하세요.")
t('인증', lambda: f"[{pick(CARDS)}] 온라인 결제 인증번호 {otp()} 입니다. 본인이 요청하지 않은 경우 고객센터로 연락해주세요.")
t('인증', lambda: f"[쿠팡] 인증번호는 {otp()}입니다. 쿠팡 직원은 인증번호를 절대 묻지 않습니다.")
t('인증', lambda: f"{otp(6)}은(는) Instagram 인증 코드입니다.")
t('인증', lambda: f"{otp(6)}은(는) [{pick(SVC)}] 로그인 인증번호입니다.")
# --- 카드/결제 ---
t('카드', lambda: f"[{pick(CARDS)}] 승인 {amt()}원 일시불 {pick(STORES)}")
t('카드', lambda: f"{pick(CARDS)} {l4()}승인 {name()}님 {amt(10000, 400000)}원 {pick([2, 3, 6])}개월 할부 {md()} {pick(STORES)}")
t('카드', lambda: f"[{pick(CARDS)}] 해외결제 승인 USD {R.randint(5, 120)}.00 {md()} AMAZON 본인이 사용하신 경우 무시하셔도 됩니다.")
t('카드', lambda: f"[{pick(CARDS)}] {ym()} 결제 예정 금액 {amt(30000, 900000)}원 안내. 결제일 {pay()}일. 결제계좌 잔액을 확인해주세요.")
t('카드', lambda: f"[{pick(CARDS)}] 청구서가 발행되었습니다. 이번 달 청구금액 {amt(30000, 900000)}원 (결제일 {pay()}일)")
t('카드', lambda: f"[삼성페이] {pick(STORES)} {amt()}원 결제 완료")
t('카드', lambda: f"[{pick(BANKS)}] {name()}님 체크카드 {amt()}원 승인. 잔액 {bal()}원")
t('카드', lambda: f"[카카오페이] {pick(STORES)}에서 {amt()}원 결제되었습니다.")
t('카드', lambda: f"[네이버페이] 결제 완료: {pick(ITEMS)} {amt()}원")
t('카드', lambda: f"{pick(CARDS)} 승인취소 {amt()}원 {pick(STORES)} {md()}")
# --- 은행/금융 ---
t('금융', lambda: f"[{pick(BANKS)}] {md()} {tm()} 입금 {amt(10000, 2000000)}원 잔액 {bal()}원 {name()}")
t('금융', lambda: f"[{pick(BANKS)}] {md()} 출금 {amt(10000, 900000)}원 {pick(['공과금', '자동이체', 'ATM'])} 잔액 {bal()}원")
t('금융', lambda: f"[{pick(BANKS)}] 대출 이자 {amt(50000, 700000)}원이 {pay()}일에 자동이체될 예정입니다. 계좌 잔액을 확인해주세요.")
t('금융', lambda: f"[{pick(BANKS)}] 만기도래 안내: {name()}님의 정기예금이 {md()}에 만기됩니다.")
t('금융', lambda: f"[토스] {name()}님에게 {amt(5000, 300000)}원을 받았어요.")
t('금융', lambda: f"[카카오뱅크] {name()}님이 {amt(5000, 300000)}원을 보냈어요. 메시지: 점심값")
t('금융', lambda: f"[{pick(SECS)}] 주식 체결 안내: {pick(STOCKS)} {R.randint(1, 30)}주 매수 체결 (체결가 {R.randrange(30000, 400000, 100):,}원)")
t('금융', lambda: f"[{pick(BANKS)}] 적금 자동이체 {amt(50000, 500000)}원이 정상적으로 처리되었습니다.")
t('금융', lambda: f"[{pick(BANKS)}] 은행은 어떠한 경우에도 보안카드 번호나 비밀번호를 요구하지 않습니다. 피싱 문자를 주의하세요.")
t('금융', lambda: f"[{pick(BANKS)}] 이번 달 신용점수가 업데이트되었습니다. 앱에서 확인해 보세요.")
# --- 공공기관 ---
t('공공', lambda: f"[국민건강보험] {name()}님의 {ym()} 건강보험료 {amt(50000, 300000)}원이 {pay()}일 자동이체 예정입니다.")
t('공공', lambda: f"[국민연금공단] {ym()}분 국민연금 납부 안내입니다. 납부 마감일은 {pay()}일입니다.")
t('공공', lambda: f"[국세청] 부가가치세 신고 납부 기한은 {md()}까지입니다. 자세한 내용은 홈택스(www.hometax.go.kr)에서 확인하세요.")
t('공공', lambda: f"[행정안전부] 오늘 {tm()} 호우주의보가 발효되었습니다. 저지대 침수에 유의하세요.")
t('공공', lambda: f"[{pick(CITY)}시] 생활쓰레기 배출 요일이 {day()}로 변경됩니다.")
t('공공', lambda: f"[정부24] 신청하신 주민등록등본 발급이 완료되었습니다. 정부24에서 확인하세요.")
t('공공', lambda: f"[한국도로공사] 하이패스 통행료 {amt(1000, 20000)}원이 {md()}에 정산되었습니다.")
t('공공', lambda: f"[{pick(CITY)}시] 예방접종 안내: {md()} {pick(HOSP)}에서 독감 무료접종이 진행됩니다. 신분증을 지참해 주세요.")
t('공공', lambda: f"[교통안전공단] 자동차 정기검사 만료일이 {md()}입니다. 기한 내 검사를 받아주세요.")
t('공공', lambda: f"[한국전력] {ym()} 전기요금 {amt(15000, 120000)}원 납부기한 {md()}. 자동이체 신청 시 요금이 감면됩니다.")
# --- 통신사 ---
t('통신', lambda: f"[{pick(TELCOS)}] {name()}님, {ym()} 이용요금 {amt(30000, 120000)}원 청구되었습니다. 납부일 {pay()}일")
t('통신', lambda: f"[{pick(TELCOS)}] {md()} 기준 데이터 잔여량 {R.randint(1, 40)}GB 입니다.")
t('통신', lambda: f"[{pick(TELCOS)}] 요금제 변경이 완료되었습니다. 변경된 요금제는 {md()}부터 적용됩니다.")
t('통신', lambda: f"[{pick(TELCOS)}] 로밍 서비스가 {pick(['일본', '미국', '태국', '베트남'])}에서 정상 개통되었습니다. 즐거운 여행 되세요.")
t('통신', lambda: f"[{pick(TELCOS)}] 고객님의 멤버십 포인트 {R.randint(500, 9000)}점이 {md()}에 소멸될 예정입니다.")
t('통신', lambda: f"[알뜰폰] 요금 미납 안내: {ym()} 요금 {amt(15000, 60000)}원이 아직 납부되지 않았습니다. 납부일까지 입금해주세요.")
# --- 예약/서비스 ---
t('예약', lambda: f"[{pick(HOSP)}] {name()}님 {md()} {tm()} 진료 예약이 확정되었습니다. 10분 전까지 접수해 주세요.")
t('예약', lambda: f"[{pick(HOSP)}] 내일 {tm()} 예약 안내입니다. 변경이 필요하시면 전화 주세요.")
t('예약', lambda: f"[CGV] 예매가 완료되었습니다. {md()} {tm()} {pick(['스파이더맨', '범죄도시', '인사이드 아웃', '서울의 봄'])} {pick(['수원', '화성', '판교', '용산'])}점")
t('예약', lambda: f"[야놀자] {md()} 숙박 예약이 확정되었습니다. 체크인 15:00")
t('예약', lambda: f"[대한항공] {md()} 출발 항공편 탑승 수속이 시작되었습니다. 공항에서 뵙겠습니다.")
t('예약', lambda: f"[코레일] {md()} {tm()} 열차 승차권이 발권되었습니다.")
t('예약', lambda: f"[배달의민족] {pick(STORES)} 주문이 접수되었습니다. 예상 도착 시간은 {R.randint(20, 50)}분입니다.")
t('예약', lambda: f"[쿠팡이츠] 배달이 시작되었어요. 도착 예정 {tm()}")
t('예약', lambda: f"[헤어샵] {name()} 고객님 {md()} {tm()} 예약 확인드립니다.")
t('예약', lambda: f"[세탁소] 맡기신 세탁물이 준비되었습니다. 찾으러 오세요.")
# --- 학교/직장/공지 ---
t('공지', lambda: f"[{pick(CITY)}초등학교] 학부모님께: {md()} 현장체험학습 안내문을 가정통신문으로 발송했습니다.")
t('공지', lambda: f"[학원] {name()} 학생 오늘 수업에 결석했습니다. 확인 부탁드립니다.")
t('공지', lambda: f"[도서관] 대출하신 도서의 반납 기한이 {md()}입니다. 연장은 도서관 홈페이지에서 가능합니다.")
t('공지', lambda: f"[관리사무소] {md()} 오전 {tm()} 단지 내 소독이 진행됩니다. 창문을 닫아 주세요.")
t('공지', lambda: f"[회사] 내일 팀 회의는 {tm()} 회의실 {R.randint(2, 9)}에서 진행됩니다.")
t('공지', lambda: f"[동아리] 이번 주 모임은 {day()} 저녁 {tm()}에 {pick(['학교 앞 카페', '학생회관', '강남역'])}에서 합니다. 참석 여부 알려주세요.")
# --- 정상 링크 포함 안내 ---
t('링크', lambda: f"[당근] {name()}님, 관심 이웃이 새 글을 올렸어요. https://www.daangn.com", 2)
t('링크', lambda: f"[네이버] 새로운 기기에서 로그인되었습니다. 본인이 아니라면 https://nid.naver.com 에서 비밀번호를 변경하세요.", 2)
t('링크', lambda: f"[Google] 새 기기에서 로그인했습니다. 본인이 아니면 https://myaccount.google.com/security 에서 확인하세요.", 2)
t('링크', lambda: f"[카카오] 카카오계정 로그인 알림: 새로운 기기에서 로그인되었습니다. https://accounts.kakao.com", 2)
t('링크', lambda: f"[토스] 송금 내역을 확인하세요 https://toss.im", 2)
# --- 가족·지인 일상 대화 (송금 요청이 없는 정상 대화: 가족 사칭 스미싱과 구분) ---
FAM = [lambda: "엄마 오늘 저녁에 집에 갈게. 뭐 사갈까?", lambda: "아들 밥은 먹었어? 오늘은 일찍 들어와~",
       lambda: f"누나 내일 약속 몇 시에 볼까? 난 {tm()} 괜찮아", lambda: "엄마 나 오늘 야근이라 늦어. 저녁 먹고 먼저 자",
       lambda: "아빠 퇴근했어? 가는 길에 우유 좀 사다 줘", lambda: "엄마 이번 주말에 할머니 댁 가는 거 맞지? 몇 시에 출발해?",
       lambda: "이모 생신 축하드려요! 주말에 찾아뵐게요", lambda: f"형 오늘 축구 몇 시에 모여? 장소 알려줘",
       lambda: "딸 시험 잘 봤어? 끝나면 전화해", lambda: "엄마 생신 선물 같이 사자. 한 사람당 얼마 정도 생각해?",
       lambda: f"엄마 나 폰 새로 샀어! 사진 찍어서 보내줄게", lambda: "아빠 나 지금 지하철이야. 곧 도착해",
       lambda: f"삼촌 {day()}에 시간 되세요? 같이 점심 먹어요", lambda: "엄마 택배 온 거 있어? 내 거 맞으면 방에 둬줘",
       lambda: "언니 나 오늘 병원 갔다 왔는데 감기래. 약 먹고 쉴게"]
for f in FAM: t('가족대화', f, 2)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--base', required=True); ap.add_argument('--out', default='.')
    a = ap.parse_args()
    rows, seen = [], set()
    for cat, fn, k in T:
        made = 0
        for _ in range(k * 4):                       # 중복이면 다시 뽑는다
            if made >= k: break
            s = fn()
            if R.random() < 0.5 and cat not in ('가족대화', '인증'): s = '[Web발신] ' + s
            key = re.sub(r'\s+', '', s)
            if key in seen: continue
            seen.add(key); rows.append((s, cat)); made += 1
    syn = pd.DataFrame(rows, columns=['content', 'category'])
    syn.to_csv(os.path.join(a.out, 'synthetic_normal.csv'), index=False, encoding='utf-8-sig')

    base = pd.read_csv(a.base, encoding='utf-8-sig')
    add = pd.DataFrame({'id': range(base.id.max() + 1, base.id.max() + 1 + len(syn)), 'content': syn.content, 'label': 0, 'label_name': '정상',
                        'split': 'train', 'source': 'synthetic_normal', 'kind': 'sms_like', 'reason': '합성 정상(직접 작성):' + syn.category,
                        'group': syn.content.map(group_key)})
    out = pd.concat([base, add], ignore_index=True)
    out.to_csv(os.path.join(a.out, 'dataset_v3.csv'), index=False, encoding='utf-8-sig')
    print(f'합성 정상 {len(syn)}건 (템플릿 {len(T)}개) → dataset_v3.csv {len(out):,}행')
    print(syn.category.value_counts().to_dict())

if __name__ == '__main__':
    main()
