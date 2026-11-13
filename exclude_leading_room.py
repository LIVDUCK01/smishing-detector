# -*- coding: utf-8 -*-
"""
투자 리딩방 문자를 학습 데이터와 평가셋에서 제외한다. (원본 파일은 수정하지 않고 새 파일로 저장)

  python exclude_leading_room.py --data data_prep\\dataset_v3.csv --eval data_prep\\eval_set.csv --outdir data_prep

출력
  dataset_v4.csv            리딩방 제외한 학습 데이터
  eval_set_v2.csv           '스팸-투자' 카테고리 제외한 평가셋
  leading_room_removed.csv  제외된 행 목록 (반드시 눈으로 확인할 것)
"""
import argparse
import os
import pandas as pd

LEADING = (r'리딩|수익률|수익\s*보장|수-익이|매매기법|족집게|재테크\s*투자'
           r'|투자.{0,6}(수익|보장|상담)|종목.{0,8}(공유|추천|상담)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True)
    ap.add_argument('--eval', required=True)
    ap.add_argument('--outdir', default='.')
    a = ap.parse_args()

    d = pd.read_csv(a.data, encoding='utf-8-sig')
    content = d.content.astype(str)
    hit = d.label.isin([1, 2]) & content.str.contains(LEADING, regex=True)
    hit &= ~content.str.contains(r'구매대행|해외송금', regex=True)   # 송금 대행 부업 사기는 제외 대상이 아님

    d[hit].to_csv(os.path.join(a.outdir, 'leading_room_removed.csv'), index=False, encoding='utf-8-sig')
    d[~hit].to_csv(os.path.join(a.outdir, 'dataset_v4.csv'), index=False, encoding='utf-8-sig')

    e = pd.read_csv(a.eval, encoding='utf-8-sig')
    ehit = e.category.astype(str).str.contains('투자')
    e[~ehit].to_csv(os.path.join(a.outdir, 'eval_set_v2.csv'), index=False, encoding='utf-8-sig')

    print(f'학습 데이터: {len(d)} → {(~hit).sum()}건 (제외 {hit.sum()}건: {d[hit].label_name.value_counts().to_dict()})')
    print(f'평가셋: {len(e)} → {(~ehit).sum()}건 (제외 {ehit.sum()}건)')
    print('다음 단계: leading_room_removed.csv 를 열어 오삭제가 없는지 확인')


if __name__ == '__main__':
    main()