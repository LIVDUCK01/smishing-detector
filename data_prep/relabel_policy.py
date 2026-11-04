# -*- coding: utf-8 -*-
"""
수동검수에서 '정상(0)'으로 분류된 문자 중, 광고·대출·구인·카톡 유도 문자를 팀 기준에 맞게 다시 분류한다.
  정상(0)  : 실제 서비스가 보낸 정상 알림만
  스미싱(2): 은행·금융·결제사를 사칭한 대출/금융 광고, 결제승인 사칭, 신청한 적 없는 대출 승인 유도
  스팸(1)  : 구인·월변·개인 카톡 유도 등 그 밖의 광고
실행: python relabel_policy.py --dataset dataset_v2_reviewed.csv --out .
산출: dataset_v2_final.csv, policy_changes.csv(변경 내역)
"""
import argparse, os, re, zlib
import pandas as pd

AD     = re.compile(r'\(광고\)|무료거부|수신거부')
FIN    = re.compile(r'은행|새마을금고|농협|신한|우리|하나|국민|저축은행|SBI|OK저축|캐피탈|카드|이니시스|페이|금융|대출|전세자금')
LOANKW = re.compile(r'대출|금리|한도|전세자금|연\s?\d|최대\s?\d|기준\s?\d|승인|결제완료|청구')
JOB    = re.compile(r'모집|구인|직원|사원|인력|채용|일당|월변|알바|채권회수|급여|페이')
KAKAO  = re.compile(r'카톡|카똑|k톡|톡ㄱ|텔레그램|문의\s?01\d|저장후\s?01\d')

FAMILY = re.compile(r'(누나|언니|숙모|엄마|아빠|오빠|형|삼촌|이모|고모|나야|아들|딸).*(송금|이체|결제|기프트\s?카드|인증서|부탁)', re.S)
PAYFAKE = re.compile(r'(승인완료|결제완료|처리완료|확인완료|출고|배송예정|인증완료|주문완료|완료\s?번호).*(문의|고객상담|고객센터|\d{2,3}-\d{3,4}-\d{4})', re.S)
GAMBLE = re.compile(r'골드머니|게임랜드|sws치로|\.cOm|스투라이크|<예측>|야구E벤|불금')
AGENCY = re.compile(r'\[복지로\]|Taourl')

def decide2(t):
    """1차 정책으로 안 잡힌 '수동검수 정상'을 한 번 더 점검. 정상 근거가 없으면 -1(학습 제외)."""
    if FAMILY.search(t):  return 2, '가족·지인 사칭 송금 요청'
    if PAYFAKE.search(t): return 2, '결제·구매 완료 사칭(문의 전화 유도)'
    if GAMBLE.search(t):  return 1, '도박·게임 홍보'
    if AGENCY.search(t):  return 2, '기관 사칭 단축 URL'
    return -1, '정상 근거 없음(원본이 phishing/spam 출처, 외국어·무의미·판단불가) → 학습 제외'

def decide(t):
    """(새 라벨, 규칙명) 또는 None(변경 없음)"""
    ad, fin, loan, job, kk = (bool(x.search(t)) for x in (AD, FIN, LOANKW, JOB, KAKAO))
    if kk and re.search(r'신청하신.*(대출|승인)|승인나오', t):         return 2, '신청한 적 없는 대출 승인 유도'
    if ad and fin and loan and not job:                              return 2, '금융·결제사 사칭 광고(대출·결제)'
    if ad and (job or kk):                                           return 1, '구인·월변·카톡 유도 광고'
    if kk and loan:                                                  return 1, '개인 카톡 유도(대출)'
    return None

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--dataset', required=True); ap.add_argument('--out', default='.')
    ap.add_argument('--checked', help='policy_changes.csv에 확인라벨(0/1/2) 열을 채운 xlsx/csv. 채운 행만 덮어쓴다')
    a = ap.parse_args()
    d = pd.read_csv(a.dataset, encoding='utf-8-sig')
    names = {0: '정상', 1: '스팸', 2: '스미싱'}
    ch = []
    for i, row in d[(d.reason == '수동검수') & (d.label == 0)].iterrows():
        r = decide(row.content)
        if r:
            ch.append({'id': row.id, 'content': row.content, '기존': '정상', '변경': names[r[0]], '규칙': r[1]})
            d.at[i, 'label'], d.at[i, 'label_name'], d.at[i, 'reason'] = r[0], names[r[0]], f'정책재분류:{r[1]}'
    for i, row in d[(d.reason == '수동검수') & (d.label == 0)].iterrows():   # 2차 점검
        lab, why = decide2(row.content)
        ch.append({'id': row.id, 'content': row.content, '기존': '정상', '변경': {**names, -1: '제외'}[lab], '규칙': why})
        d.at[i, 'label'], d.at[i, 'label_name'], d.at[i, 'reason'] = lab, {**names, -1: '검수필요'}[lab], f'정책재분류:{why}'
        if lab == -1: d.at[i, 'split'] = 'review'
    n_checked = 0
    if a.checked:                                                    # 사람이 확인한 라벨이 규칙보다 우선
        c = pd.read_excel(a.checked) if a.checked.endswith('.xlsx') else pd.read_csv(a.checked, encoding='utf-8-sig')
        c = c[c['확인라벨'].isin([0, 1, 2])]
        known = d[d.split != 'review'].groupby('group').split.first().to_dict()
        for _, row in c.iterrows():
            i = d.index[d.id == row['id']][0]; lab = int(row['확인라벨'])
            d.at[i, 'label'], d.at[i, 'label_name'], d.at[i, 'reason'] = lab, names[lab], '확인라벨(수동)'
            if d.at[i, 'split'] == 'review':                         # 제외였던 행은 그룹 기준으로 split 배정
                g = d.at[i, 'group']; d.at[i, 'split'] = known.get(g, 'test' if zlib.crc32(str(g).encode()) % 5 == 0 else 'train')
            for x in ch:
                if x['id'] == row['id']: x['변경'] = names[lab]; x['규칙'] = '확인라벨(수동)'
            n_checked += 1
    pd.DataFrame(ch).to_csv(os.path.join(a.out, 'policy_changes.csv'), index=False, encoding='utf-8-sig')
    d.to_csv(os.path.join(a.out, 'dataset_v2_final.csv'), index=False, encoding='utf-8-sig')
    print(f'수동 확인 반영 {n_checked}건')
    print(f'변경 {len(ch)}건:', pd.DataFrame(ch)['규칙'].value_counts().to_dict() if ch else {})
    print(d.groupby(['label_name', 'split']).size().unstack(fill_value=0))

if __name__ == '__main__':
    main()
