# -*- coding: utf-8 -*-
"""
원본 2개(GitHub KOR_phishing, HuggingFace lgaidataset)로 3분류 데이터셋을 다시 만든다.
  라벨: 0=정상, 1=스팸(도박·성인·불법광고), 2=스미싱(사칭·유도), -1=검수필요(학습 제외)
실행: python build_dataset.py --github GitHub_KOR_phishing_data_raw.csv --hf HuggingFace_lgaidataset.csv --out .
필요: pandas, scikit-learn
"""
import argparse, re, os
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

# ---------- 규칙 (정규식) ----------
MASK = re.compile(r'\*|[ⓐ-ⓩⒶ-Ⓩ①-⑳㉠-㉿♠♥♣♦❥♡♤★☆]')   # ㈜ 등 상호 표기는 마스킹 아님
URL  = re.compile(r'https?://|www\.|\b[a-z0-9\-]+\.(?:com|net|kr|me|ly|gl|do|xyz|top|cc|in|us|vip|site|pro|kim|mba|wiki)\b', re.I)

# 스팸: 도박·성인·불법광고 (넓은 단어 '이벤트/포인트/지급/게임' 등은 제외)
SPAM = re.compile(r'카지노|슬롯|바카라|토토|배팅|베팅|올인|먹튀|첫충|매충|입플|환전|무료머니|룰렛|토사장|총판|배당|꽁머니|홀덤|'
                  r'성인|만남|오피|유흥|조건만남|야한|출장|애인|미러링')
AD   = re.compile(r'\(광고\)|무료거부|수신거부')
LOAN = re.compile(r'대출|금리|한도|저금리|채무|햇살론|새희망|정부지원|생활안정자금|서민')

# 스미싱: 사칭·유도 유형별 (유형명, 정규식)
SMISH = [
 ('가족사칭', re.compile(r'(엄마|아빠|아들|딸)')),                      # 아래에서 보조 단서와 함께 판정
 ('택배사칭', re.compile(r'(택배|배송|배달|송장|운송장|미배달|주소불명|주소지|도로명|반송|집하|분실).*(CJ|대한통운|한진|롯데|우체국|쿠팡|로젠|주소|수정|보상|미확인|확인|재배송|http|www|\.com|\.pro|\.info|\.kr)', re.S)),
 ('기관사칭', re.compile(r'건강검진|검진|통지서|질병관리청|공단|건강관리협회|백신|예방접종|증명서|진단결과|진단서|민원|과태료|범칙금|국민연금|건강보험|보험금|국세청|세금|환급금|재난지원금|지원대상|경찰|검찰|법원|소환|출석')),
 ('계정·금융', re.compile(r'(로그인|해외\s?IP|IP-|본인확인|본인인증|계정|비밀번호|보안\s?센터|보안\s?업그레이드).*(은행|카드|코인|업비트|빗썸|코인원|토스|카카오|네이버|MEXC|OKX|XT|거래소|http|www|\.com)|'
                          r'(코인원|업비트|빗썸|MEXC|OKX|토스|카카오뱅크|국민은행|신한은행|우리은행|하나은행|농협).*(로그인|해외|인증|차단|정지|확인)|'
                          r"verify your account|can.t verify|KYC|보안\s?센터.*업그레이드", re.S|re.I)),
 ('결제승인사칭', re.compile(r'(해외승인|승인번호|결제완료|결제내역|승인코드|해외인증|KRW|USD).*(문의|신고|센터|소비자|070|\d{2,4}-\d{3,4}-\d{4})', re.S)),
 ('부고·청첩', re.compile(r'부고|부음|별세|청첩|결혼식|모바일\s?초대장')),
]
FAM_HELP = re.compile(r'고장|액정|수리|문자나라|컴퓨터|컴터|피씨|대리구매|상품권|문상|기프트|계좌|비밀번호|급해|급한|입금|이체|인증')

def norm_ws(s):  return re.sub(r'\s+', ' ', str(s)).strip()
def key_nospace(s): return re.sub(r'\s+', '', s)
def group_key(s):
    """근접중복 그룹키: 공백·숫자·마스킹기호 제거"""
    t = MASK.sub('', s.lower()); t = re.sub(r'\d+', '0', t); return re.sub(r'\s+', '', t)

def smish_type(t):
    for name, rx in SMISH:
        if rx.search(t):
            if name == '가족사칭' and not FAM_HELP.search(t): continue
            return name
    return None

def label_positive(t, source, loan_policy):
    """스팸/스미싱 후보 한 문장을 (라벨, 근거)로. 1=스팸, 2=스미싱, -1=검수필요"""
    m, sm, sp = bool(MASK.search(t)), smish_type(t), bool(SPAM.search(t))
    loan = bool(AD.search(t) and LOAN.search(t))
    if source == 'github':                       # GitHub 데이터셋은 원래 'phishing' 라벨 → 존중
        if sp and not sm:  return 1, '원본phishing이나 도박·성인 키워드(스팸)'
        if sm:             return 2, f'스미싱:{sm}(원본라벨)'
        if loan:           return ({'smishing': 2, 'spam': 1, 'review': -1}[loan_policy], '대출광고(원본라벨 phishing)')
        return 2, '스미싱:원본라벨 phishing(유형 미분류)'
    # HF 클래스2: 스팸과 스미싱이 섞여 있어 규칙으로 분리
    if sp and not sm:                  return 1, '도박·성인 키워드'
    if sm and not m and not sp:        return 2, f'스미싱:{sm}'
    if sm and (m or sp):               return -1, f'충돌(스미싱:{sm} + 마스킹/스팸)'
    if loan:                           return ({'smishing': 2, 'spam': 1, 'review': -1}[loan_policy], '대출광고')
    if m:                              return 1, '마스킹·난독화(스팸 추정)'
    if URL.search(t) or re.search(r'\[FW\]|FW', t): return 1, '난독화 도메인 홍보(스팸 추정)'
    return -1, '근거 부족'

def load(path):
    return pd.read_csv(path, encoding='utf-8-sig')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--github', required=True); ap.add_argument('--hf', required=True)
    ap.add_argument('--out', default='.'); ap.add_argument('--chat_cap', type=int, default=8000,
                    help='일상 대화형 정상 문장 최대 개수(길이 편향 완화)')
    ap.add_argument('--tmpl_cap', type=int, default=10, help='동일 템플릿 정상 문자 최대 개수')
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--loan_policy', choices=['smishing','spam','review'], default='smishing',
                    help='(광고)+대출 문자를 어떻게 볼지. 계획서의 "대출 사기" 범위를 고려해 기본은 smishing')
    a = ap.parse_args()

    g, h = load(a.github), load(a.hf)
    rows = []
    for _, r in g.iterrows(): rows.append((norm_ws(r['content']), 'github', int(r['class']), 'pos' if r['class']==1 else 'neg'))
    for _, r in h.iterrows():
        if r['class'] == 2:   rows.append((norm_ws(r['content']), 'hf_c2', 2, 'pos'))
        elif r['class'] == 1: rows.append((norm_ws(r['content']), 'hf_c1_comment', 1, 'neg'))
        else:                 rows.append((norm_ws(r['content']), 'hf_c3_delivery', 3, 'neg'))
    df = pd.DataFrame(rows, columns=['content', 'source', 'raw_class', 'side'])
    df = df[df.content.str.len() >= 5]                         # 5자 미만 제거
    df = df[~df.content.str.contains(r'^#NAME\?$')]             # 엑셀 오류 문자열 제거
    df['k'] = df.content.map(key_nospace)
    n0 = len(df); df = df.drop_duplicates('k').copy()           # 공백 무시 중복 제거
    # 한글이 거의 없는 문장(깨진 데이터) 제거: 정상 쪽만 (스팸은 난독화로 한글이 적을 수 있음)
    hangul = df.content.map(lambda s: len(re.findall('[가-힣]', s)) / max(len(s), 1))
    df = df[~((df.side == 'neg') & (hangul < 0.1))].copy()

    # ---- 라벨링 ----
    lab, why = [], []
    for t, side, src in zip(df.content, df.side, df.source):
        if side == 'neg': lab.append(0); why.append('정상(원본 라벨)')
        else:
            l, w = label_positive(t, src, a.loan_policy); lab.append(l); why.append(w)
    df['label'], df['reason'] = lab, why

    # ---- 정상 쪽 정리: 템플릿 반복 제한 + 일상대화 비중 제한 ----
    neg = df[df.label == 0].copy()
    sms_like = neg.content.str.contains(r'발신|url:|https?://|인증번호|택배|배송|승인|결제|\[[^\]]{2,12}\]')
    neg['kind'] = sms_like.map({True: 'sms_like', False: 'chat'})
    skeleton = neg.content.map(lambda s: re.sub(r'[가-힣]+', '', re.sub(r'\d+', '0', s)))
    templated = neg.content.str.contains(r'발신|url:')
    neg['skel'] = skeleton
    keep_t = neg[templated].groupby('skel', group_keys=False).apply(lambda x: x.sample(min(len(x), a.tmpl_cap), random_state=a.seed))
    neg2 = pd.concat([neg[~templated], keep_t])
    chat = neg2[neg2.kind == 'chat']
    chat = chat.sample(min(len(chat), a.chat_cap), random_state=a.seed)
    neg3 = pd.concat([neg2[neg2.kind != 'chat'], chat])
    dropped_neg = len(neg) - len(neg3)

    pos = df[df.label != 0].copy(); pos['kind'] = 'pos'
    out = pd.concat([neg3.drop(columns=['skel']), pos]).reset_index(drop=True)
    out['group'] = out.content.map(group_key)

    # ---- 분할: 라벨 확정된 것만, 근접중복 그룹 단위, 클래스 비율 유지 ----
    conf = out[out.label >= 0].copy()
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=a.seed)
    _, test_idx = next(sgkf.split(conf, conf.label, groups=conf.group))
    conf['split'] = 'train'; conf.iloc[test_idx, conf.columns.get_loc('split')] = 'test'
    out['split'] = 'review'; out.loc[conf.index, 'split'] = conf['split']

    names = {0: '정상', 1: '스팸', 2: '스미싱', -1: '검수필요'}
    out['label_name'] = out.label.map(names)
    out.insert(0, 'id', range(1, len(out) + 1))
    cols = ['id', 'content', 'label', 'label_name', 'split', 'source', 'kind', 'reason', 'group']
    os.makedirs(a.out, exist_ok=True)
    out[cols].to_csv(os.path.join(a.out, 'dataset_v2.csv'), index=False, encoding='utf-8-sig')
    out[out.label == -1].sort_values('reason')[['id', 'content', 'reason', 'source']].assign(검수라벨='') \
       .to_csv(os.path.join(a.out, 'review_needed.csv'), index=False, encoding='utf-8-sig')

    print(f'원본 합계 {len(g)+len(h):,} → 중복·잡음 제거 후 {len(df):,} → 정상 정리로 {dropped_neg:,}건 제외 → 최종 {len(out):,}')
    print(out.groupby(['label_name', 'split']).size().unstack(fill_value=0))
    print('\n검수필요 사유 분포:'); print(out[out.label == -1].reason.str.replace(r'\(.*', '', regex=True).value_counts().to_string())
    print('\n정상 종류:', out[out.label == 0].kind.value_counts().to_dict())
    print('스미싱 유형:', out[out.label == 2].reason.str.replace(r'\(.*','',regex=True).value_counts().to_dict())

if __name__ == '__main__':
    main()
