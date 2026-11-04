# -*- coding: utf-8 -*-
"""
검수 결과(review_needed_labeled.xlsx)를 dataset_v2.csv에 반영한다.
  - 검수라벨: 0=정상, 1=스팸, 2=스미싱 (빈칸은 제외)
  - 규칙과 크게 어긋나는 라벨은 '의심'으로 따로 뽑아(review_audit.csv) 재확인 전까지 학습에서 제외한다.
    (--trust_all 을 주면 의심 여부와 상관없이 검수 결과를 그대로 반영)
실행: python apply_review.py --dataset dataset_v2.csv --review review_needed_labeled.xlsx --out .
재검수 반영: ... --audit review_audit_labeled.csv  (review_audit.csv의 '재검수라벨' 열을 채운 파일)
"""
import argparse, os, re, zlib
import pandas as pd
from build_dataset import smish_type, SPAM, MASK, AD, LOAN, group_key

PHONE070 = re.compile(r'\b070-?\d{3,4}-?\d{4}\b')
NAMES = {0: '정상', 1: '스팸', 2: '스미싱', -1: '검수필요'}

def audit_reason(text, lab):
    """검수라벨이 규칙 신호와 충돌하면 사유를 돌려준다(없으면 '')."""
    sp, sm = bool(SPAM.search(text)), smish_type(text)
    loan_ad = bool(AD.search(text) and LOAN.search(text))
    if lab == 0:
        if sp:        return '정상으로 검수했으나 도박·성인 키워드 포함'
        if sm:        return f'정상으로 검수했으나 사칭 유형({sm}) 신호'
        if PHONE070.search(text): return '정상으로 검수했으나 070 번호 포함'
        if loan_ad:   return '정상으로 검수했으나 (광고)+대출 문구(스미싱 정책과 불일치)'
    if lab == 2 and sp and not sm: return '스미싱으로 검수했으나 도박·성인 키워드만 있음(스팸 가능)'
    if lab == 1 and sm and not sp: return f'스팸으로 검수했으나 사칭 유형({sm}) 신호'
    return ''

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True); ap.add_argument('--review', required=True)
    ap.add_argument('--out', default='.'); ap.add_argument('--trust_all', action='store_true')
    ap.add_argument('--audit', help='의심 목록(review_audit.csv)에 재검수라벨을 채운 파일')
    a = ap.parse_args()
    d = pd.read_csv(a.dataset, encoding='utf-8-sig')
    r = pd.read_excel(a.review) if a.review.endswith('.xlsx') else pd.read_csv(a.review, encoding='utf-8-sig')
    r = r[r['검수라벨'].isin([0, 1, 2])].copy(); r['검수라벨'] = r['검수라벨'].astype(int)
    r['audit'] = [audit_reason(t, l) for t, l in zip(r.content, r.검수라벨)]
    if a.audit:                                                       # 재검수 결과가 있으면 우선 적용
        fix = pd.read_csv(a.audit, encoding='utf-8-sig'); fix = fix[fix['재검수라벨'].isin([0, 1, 2])]
        m = dict(zip(fix['id'], fix['재검수라벨'].astype(int)))
        r['검수라벨'] = [m.get(i, l) for i, l in zip(r['id'], r['검수라벨'])]
        r['audit'] = ['' if i in m else x for i, x in zip(r['id'], r['audit'])]
    aud = r[r.audit != ''][['id', 'content', '검수라벨', 'audit', 'source']].assign(재검수라벨='')
    aud.to_csv(os.path.join(a.out, 'review_audit.csv'), index=False, encoding='utf-8-sig')

    ok = r if a.trust_all else r[r.audit == '']
    existing = d[d.split != 'review']
    group_split = existing.groupby('group').split.first().to_dict()        # 같은 그룹은 같은 split
    for _, row in ok.iterrows():
        i = d.index[d.id == row['id']][0]
        g = d.at[i, 'group'] if isinstance(d.at[i, 'group'], str) else group_key(row['content'])
        d.at[i, 'label'] = row['검수라벨']; d.at[i, 'label_name'] = NAMES[row['검수라벨']]
        d.at[i, 'reason'] = '수동검수'
        d.at[i, 'split'] = group_split.get(g, 'test' if zlib.crc32(g.encode()) % 5 == 0 else 'train')
    d.to_csv(os.path.join(a.out, 'dataset_v2_reviewed.csv'), index=False, encoding='utf-8-sig')

    print(f'검수 {len(r)}건 중 반영 {len(ok)}건 / 의심 {len(aud)}건(review_audit.csv, 학습 제외)')
    print('검수라벨 분포:', r.검수라벨.map(NAMES).value_counts().to_dict())
    print(d.groupby(['label_name', 'split']).size().unstack(fill_value=0))
    print('\n의심 사유:'); print(aud.audit.str.replace(r'\(.*?\)', '', regex=True).value_counts().to_string())

if __name__ == '__main__':
    main()
