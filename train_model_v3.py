# -*- coding: utf-8 -*-
"""
dataset_v2_final.csv 로 model.pkl / vectorizer.pkl 을 다시 만든다.
  - 기본(binary): 스미싱=1, 그 외(정상·스팸)=0  → main.py 를 고치지 않고 그대로 쓸 수 있다
                  (main.py 는 predict_proba(...)[0][1] 을 '스미싱 확률'로 읽는다)
  - --mode multi : 정상/스팸/스미싱 3분류. 이 경우 main.py 의 [0][1] 을 스미싱 열로 바꿔야 한다.
  - --compare    : Naive Bayes / SVM / 로지스틱 회귀를 같은 test 셋으로 비교해 표로 출력 (계획서의 NB·SVM 비교)
프로젝트 폴더(main.py, url_checker.py 가 있는 곳)에서 실행하세요. 모델은 사용하는 PC의 scikit-learn 으로 직접 만들어야 합니다.
  python train_model.py --data dataset_v2_final.csv --compare
  python train_model.py --data dataset_v2_final.csv --save      # model.pkl / vectorizer.pkl 저장(기존 파일은 .bak 백업)
"""
import argparse, os, re, shutil, time
import pandas as pd, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, precision_recall_fscore_support

try:                                    # 서버가 쓰는 URL 제거 함수를 그대로 사용(학습·추론 전처리 일치)
    from url_checker import strip_urls_for_ml
except Exception:                       # 단독 실행용 대체 (url_checker.py 의 임시 구현과 동일)
    _URL = re.compile(r'https?://\S+|www\.\S+|\b[a-z0-9\-]+\.(?:com|net|kr|me|ly|gl|do|xyz|top|cc|in|us|vip|site|pro|kim|mba|wiki)\S*', re.I)
    def strip_urls_for_ml(t): return re.sub(r'\s+', ' ', _URL.sub(' ', t)).strip()

SAMPLES = [("스미싱", "[Web발신] [CJ대한통운] 고객님의 택배가 주소불명으로 반송 예정입니다. 주소 재확인: http://cj-post-kr.top/a1"),
           ("스미싱", "[국민은행] 해외결제 승인 389,000원. 본인이 아닐 경우 즉시 확인 http://kbstar-secure.xyz"),
           ("스미싱", "엄마 나 폰 액정 깨져서 수리 맡겼어 이 번호로 문자 줘 급하게 100만원만 보내줘"),
           ("정상",  "[Web발신] [쿠팡] 주문하신 상품이 오늘 도착 예정입니다. 확인: https://www.coupang.com"),
           ("정상",  "[Web발신] [국민은행] 인증번호 [482913]를 입력해 주세요. 타인에게 절대 알려주지 마세요."),
           ("정상",  "[Web발신] [신한카드] 승인 15,000원 일시불 스타벅스"),
           ("정상",  "내일 저녁 7시에 강남역에서 보자 늦지 마")]

def make_models():
    return {'LogisticRegression': LogisticRegression(max_iter=1000, class_weight='balanced'),
            'NaiveBayes(Complement)': ComplementNB(alpha=0.3),
            'SVM(LinearSVC)': CalibratedClassifierCV(LinearSVC(class_weight='balanced'), cv=3)}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True); ap.add_argument('--mode', choices=['binary', 'multi'], default='binary')
    ap.add_argument('--compare', action='store_true'); ap.add_argument('--save', action='store_true')
    ap.add_argument('--out', default='.')
    ap.add_argument('--eval', help='eval_set.csv: 학습에 쓰지 않은 평가용 문자. 분류별 확률/오탐/탐지를 출력')
    a = ap.parse_args()

    d = pd.read_csv(a.data, encoding='utf-8-sig'); d = d[d.label >= 0].copy()
    d['text'] = d.content.map(strip_urls_for_ml)                      # 서버와 같은 전처리
    d = d[d.text.str.len() >= 3]
    y = (d.label == 2).astype(int) if a.mode == 'binary' else d.label
    tr, te = d.split == 'train', d.split == 'test'
    print(f'학습 {tr.sum():,} / 테스트 {te.sum():,} (mode={a.mode})  스미싱 비율 train {(d[tr].label==2).mean():.1%}, test {(d[te].label==2).mean():.1%}')

    vec = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4), min_df=3, max_features=200000, sublinear_tf=True)
    Xtr = vec.fit_transform(d[tr].text); Xte = vec.transform(d[te].text)
    pos = 1 if a.mode == 'binary' else 2

    rows, fitted = [], {}
    for name, m in make_models().items():
        if not a.compare and name != 'LogisticRegression': continue
        t0 = time.time(); m.fit(Xtr, y[tr]); fit_s = time.time() - t0
        t0 = time.time(); pred = m.predict(Xte); inf_ms = (time.time() - t0) / te.sum() * 1000
        p, r, f, _ = precision_recall_fscore_support(y[te], pred, labels=[pos], zero_division=0)
        rows.append({'모델': name, '스미싱 정밀도': round(p[0], 3), '스미싱 재현율': round(r[0], 3), '스미싱 F1': round(f[0], 3),
                     '학습(s)': round(fit_s, 1), '추론(ms/건)': round(inf_ms, 3)}); fitted[name] = m
    print('\n' + pd.DataFrame(rows).to_string(index=False))

    lr = fitted['LogisticRegression']
    print('\n[LogisticRegression 상세]'); print(classification_report(y[te], lr.predict(Xte), digits=3))
    col = list(lr.classes_).index(pos)
    print('샘플 문자 → 스미싱 확률(%)')
    for lab, t in SAMPLES:
        pr = lr.predict_proba(vec.transform([strip_urls_for_ml(t)]))[0][col] * 100
        print(f'  [{lab}] {pr:5.1f}% | {t[:44]}')

    if a.eval:
        ev = pd.read_csv(a.eval, encoding='utf-8-sig')
        pr = lr.predict_proba(vec.transform(ev.content.map(strip_urls_for_ml)))[:, col] * 100
        ev['ml_prob'] = pr
        g = ev.groupby('category').ml_prob
        rep = pd.DataFrame({'건수': g.size(), '평균확률(%)': g.mean().round(1),
                            '35%이상': ev.assign(x=pr >= 35).groupby('category').x.mean().round(2),
                            '70%이상': ev.assign(x=pr >= 70).groupby('category').x.mean().round(2)})
        print('\n[평가셋: 문구 모델 단독 결과 (서버의 URL 판정은 포함하지 않음)]'); print(rep.to_string())
        n, sm = ev[ev.label == 0], ev[ev.label == 2]
        print(f'정상 {len(n)}건 중 70% 이상(위험으로 볼 것): {(n.ml_prob >= 70).sum()}건 ({(n.ml_prob >= 70).mean():.0%}) / 35% 이상: {(n.ml_prob >= 35).mean():.0%}')
        print(f'스미싱 {len(sm)}건 중 70% 이상: {(sm.ml_prob >= 70).mean():.0%} / 35% 이상: {(sm.ml_prob >= 35).mean():.0%}')
        ev.to_csv(os.path.join(a.out, 'eval_result.csv'), index=False, encoding='utf-8-sig')

    if a.save:
        for f in ('model.pkl', 'vectorizer.pkl'):
            if os.path.exists(os.path.join(a.out, f)): shutil.copy(os.path.join(a.out, f), os.path.join(a.out, f + '.bak'))
        joblib.dump(lr, os.path.join(a.out, 'model.pkl')); joblib.dump(vec, os.path.join(a.out, 'vectorizer.pkl'))
        print('\n저장 완료: model.pkl, vectorizer.pkl (기존 파일은 .bak 으로 백업)')

if __name__ == '__main__':
    main()
