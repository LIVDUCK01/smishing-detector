# -*- coding: utf-8 -*-
"""
평가셋(eval_set.csv)으로 세 방식을 비교한다.
  A. 키워드 필터링(기존 방식)  B. 문구 ML 단독(기존 main.py 임계값)  C. 하이브리드(URL 우선, hybrid_logic.decide)
프로젝트 루트(model.pkl, url_checker.py 가 있는 곳)에서 실행:
  python evaluate.py --eval data_prep\\eval_set.csv
옵션: --checker <url_checker.py 경로>  --model-dir <model.pkl 폴더>  --online (리다이렉트 추적·VirusTotal 포함. 기본은 오프라인=정적 규칙만)
"""
import argparse, importlib.util, io, os, re, sys
import pandas as pd, joblib
from hybrid_logic import decide

# A: '기존 단순 키워드 필터링' 가정용 단어 목록
KEYWORDS = ['택배', '배송', '반송', '주소', '확인', '인증', '결제', '승인', '계좌', '대출', '과태료', '검찰', '경찰', '환급', '지원금',
            '무료거부', '광고', '이벤트', '카지노', '토토', '보너스', '입금', '바카라', '수익', '청첩', '부고', '건강검진', '통지서']

def load_checker(path, online):
    ro, re_ = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = io.TextIOWrapper(io.BytesIO(), encoding='utf-8'), io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
    try:
        sp = importlib.util.spec_from_file_location('uc_under_test', path); mod = importlib.util.module_from_spec(sp); sp.loader.exec_module(mod)
    finally:
        sys.stdout, sys.stderr = ro, re_
    if not online:
        mod.resolve_redirect = lambda url, timeout=3: url
        for n in ('check_virustotal', 'check_virustotal_domain'):
            if hasattr(mod, n): setattr(mod, n, (lambda h, **k: None) if n == 'check_virustotal' else (lambda d, **k: {'success': False}))
    return mod

URL_FALLBACK = re.compile(r'https?://\S+|www\.\S+|\b[a-z0-9\-]+\.(?:com|net|kr|me|ly|gl|do|xyz|top|cc|site|online)\S*', re.I)

def ok(verdict, expected):
    return {'안전': verdict == '안전', '주의이상': verdict in ('주의', '위험'), '위험': verdict == '위험'}[expected]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--eval', required=True); ap.add_argument('--checker', default='url_checker.py')
    ap.add_argument('--model-dir', default='.'); ap.add_argument('--online', action='store_true'); ap.add_argument('--out', default='.')
    a = ap.parse_args()

    ev = pd.read_csv(a.eval, encoding='utf-8-sig')
    mod = load_checker(a.checker, a.online)
    strip = getattr(mod, 'strip_urls_for_ml', lambda t: URL_FALLBACK.sub(' ', t))
    model, vec = joblib.load(os.path.join(a.model_dir, 'model.pkl')), joblib.load(os.path.join(a.model_dir, 'vectorizer.pkl'))
    cl = list(model.classes_); col = cl.index(2) if len(cl) > 2 else cl.index(1)

    rows = []
    for _, r in ev.iterrows():
        t = r.content
        ml = float(model.predict_proba(vec.transform([strip(t)]))[0][col] * 100)
        ur = mod.check_message_urls(t)
        us, hu, det = ur.get('max_risk_score', 0), ur.get('has_url', False), ur.get('results', [])
        h = decide(ml, hu, us, det, text=t)
        rows.append({'id': r.id, 'category': r.category, 'label': r.label_name, 'expected': r.expected_verdict,
                     'A_키워드': '주의' if any(k in t for k in KEYWORDS) else '안전',
                     'B_ML단독': '위험' if ml >= 70 else ('주의' if ml >= 35 else '안전'),
                     'C_하이브리드': h['verdict'], 'ml_prob': round(ml, 1), 'url_score': us, 'has_url': hu,
                     'link_status': h['link_status'], 'basis': h['verdict_basis'], 'content': t})
    d = pd.DataFrame(rows)
    d.to_csv(os.path.join(a.out, 'eval_compare.csv'), index=False, encoding='utf-8-sig')

    def summary(col):
        n, p = d[d.label == '정상'], d[d.label != '정상']; s = d[(d.label == '스미싱') & d.has_url]
        return {'정상 오탐률(주의이상)': f'{(n[col] != "안전").mean():.0%}', '정상 위험오탐률': f'{(n[col] == "위험").mean():.0%}',
                '스팸·스미싱 탐지율(주의이상)': f'{(p[col] != "안전").mean():.0%}',
                '링크 있는 스미싱 위험판정률': ('-' if col == 'A_키워드' else f'{(s[col] == "위험").mean():.0%}'),
                '기대판정 일치율': f'{d.apply(lambda r: ok(r[col], r.expected), axis=1).mean():.0%}'}
    tab = pd.DataFrame({'A 키워드 필터': summary('A_키워드'), 'B 문구 ML 단독': summary('B_ML단독'), 'C 하이브리드': summary('C_하이브리드')})
    print(f'평가셋 {len(d)}건 (정상 {(d.label=="정상").sum()}, 스팸 {(d.label=="스팸").sum()}, 스미싱 {(d.label=="스미싱").sum()}) | url_checker={a.checker} | {"온라인" if a.online else "오프라인(정적 규칙만)"}\n')
    print(tab.to_string())
    print('\n[하이브리드] 분류별 기대판정 일치율')
    print(d.assign(ok=d.apply(lambda r: ok(r['C_하이브리드'], r.expected), axis=1)).groupby('category').ok.agg(['mean', 'size']).round(2).rename(columns={'mean': '일치율', 'size': '건수'}).to_string())
    bad = d[~d.apply(lambda r: ok(r['C_하이브리드'], r.expected), axis=1)]
    print(f'\n[하이브리드] 기대와 다른 {len(bad)}건')
    for _, r in bad.iterrows(): print(f"  [{r.label}/{r.expected}→{r['C_하이브리드']}] ml={r.ml_prob} url={r.url_score} {r.link_status} | {r.content[:60]}")

if __name__ == '__main__':
    main()