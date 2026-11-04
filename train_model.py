# -*- coding: utf-8 -*-
"""
model.pkl / vectorizer.pkl 재학습 스크립트

[문제 상황]
- 기존 GitHub_KOR_phishing_data_raw.csv 의 '정상(class 0)' 문자 42,594개 중
  URL이 포함된 문장은 단 3개(0.007%)뿐이었음.
- 그 결과 모델이 "URL 존재 여부" 자체를 피싱의 결정적 신호로 과하게 학습해서,
  google.com 같은 완전히 안전한 URL이 포함된 정상 문장도 99% 확률로 스미싱으로 오탐.

[해결 방법]
- HuggingFace_lgaidataset.csv 의 class 3 (우체국 배달완료 등 '진짜 택배 안내문', 2,700개,
  그중 22%가 URL 포함)을 정상 데이터에 합류시켜서,
  "URL이 있어도 정상일 수 있다"는 패턴을 모델이 학습하도록 보강.

[라벨 매핑]
- GitHub:        class 0 → 정상(0)   |  class 1 → 피싱(1)
- HuggingFace:    class 1 → 정상(0, 일상대화)
                  class 2 → 피싱(1, 실제 스미싱)
                  class 3 → 정상(0, 진짜 택배 안내문)  ← 이번에 추가되는 핵심 데이터

사용법: 이 파일과 두 CSV, 기존 model.pkl/vectorizer.pkl이 있는 폴더에서
    python train_model.py
실행하면 새 model.pkl / vectorizer.pkl 이 만들어짐 (기존 파일은 자동 백업됨).
"""
import io
import sys
import shutil
import datetime

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding="utf-8")

import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# url_checker.py의 strip_urls_for_ml()을 그대로 사용 — 학습 때와 실제 서비스(main.py)에서
# 쓰는 전처리 로직이 항상 100% 똑같아야 하므로, 중복 구현하지 않고 공통 함수를 가져온다.
from url_checker import strip_urls_for_ml as strip_urls

GITHUB_CSV = "GitHub_KOR_phishing_data_raw.csv"
HF_CSV = "HuggingFace_lgaidataset.csv"

MODEL_PATH = "model.pkl"
VEC_PATH = "vectorizer.pkl"


def load_and_merge() -> pd.DataFrame:
    print("1) 데이터 불러오는 중...")
    gh = pd.read_csv(GITHUB_CSV)
    hf = pd.read_csv(HF_CSV)

    # 라벨 재매핑: 최종적으로 0=정상, 1=피싱(스미싱) 두 가지로 통일
    gh_label = gh["class"].map({0: 0, 1: 1})
    hf_label = hf["class"].map({1: 0, 2: 1, 3: 0})

    gh_part = pd.DataFrame({"content": gh["content"], "label": gh_label, "source": "github"})
    hf_part = pd.DataFrame({"content": hf["content"], "label": hf_label, "source": "huggingface"})

    merged = pd.concat([gh_part, hf_part], ignore_index=True)

    before = len(merged)
    merged = merged.dropna(subset=["content", "label"])
    merged = merged.drop_duplicates(subset=["content"])  # 두 데이터셋 간 중복 문장 제거
    after = len(merged)
    print(f"   합친 후: {before}개 → 결측/중복 제거 후: {after}개")

    print("\n2) 최종 라벨 분포")
    print(merged["label"].value_counts().rename({0: "정상(0)", 1: "피싱(1)"}))

    has_url = merged["content"].str.contains(r"http|www\.", case=False, na=False, regex=True)
    print("\n3) 정상 데이터 중 URL 포함 비율 (참고용)")
    normal_url_ratio = has_url[merged["label"] == 0].mean()
    print(f"   정상(0) 중 URL 포함: {normal_url_ratio:.2%}  (기존엔 0.007% 수준이었음)")

    print("\n4) 텍스트에서 URL 제거 중 (URL 위험도는 url_checker.py가 별도로 담당)")
    merged["content"] = merged["content"].apply(strip_urls)

    return merged


def train(merged: pd.DataFrame):
    X_train, X_test, y_train, y_test = train_test_split(
        merged["content"], merged["label"],
        test_size=0.1, random_state=42, stratify=merged["label"],
    )

    print("\n5) TF-IDF 벡터화 + 로지스틱 회귀 학습 중...")
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=0.95)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    model = LogisticRegression(class_weight="balanced", max_iter=1000)
    model.fit(X_train_vec, y_train)

    print("\n6) holdout 테스트셋(10%) 성능")
    y_pred = model.predict(X_test_vec)
    print(classification_report(y_test, y_pred, target_names=["정상(0)", "피싱(1)"]))
    print("혼동행렬 (행=실제, 열=예측):")
    print(confusion_matrix(y_test, y_pred))

    return model, vectorizer


def sanity_check(model, vectorizer):
    print("\n7) 실사용 시나리오 테스트 (이전에 오탐났던 케이스 포함)")
    cases = [
        ("확인용 테스트: http://google.com", "정상이어야 함 (안전한 URL)"),
        ("[택배] 고객님의 상품이 배송 중입니다. 운송장번호 123456789", "정상이어야 함"),
        ("(우체국 배달완료) 고객님! 소포우편물을 배송 완료하였습니다. http://ems.epost.go.kr/trace", "정상이어야 함 (URL 포함 진짜 택배 안내)"),
        ("[Web발신] 해외직구 결제 완료. 본인 아니면 확인: http://bit.ly/abc123", "피싱이어야 함"),
        ("[국제발신] 해외직구 결제 승인 완료. 본인 아닐 시 확인 요망: http://192.168.1.100:8080/secure/update.apk", "피싱이어야 함"),
    ]
    for text, expectation in cases:
        # 학습 때와 동일하게 URL을 [URL]로 치환한 뒤 예측 (학습/추론 전처리 일관성 유지)
        cleaned = strip_urls(text)
        prob = model.predict_proba(vectorizer.transform([cleaned]))[0][1] * 100
        print(f"   [{expectation}] 피싱 확률 {prob:5.1f}%  ← {text[:50]}")


def save_with_backup(model, vectorizer):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    for path in [MODEL_PATH, VEC_PATH]:
        try:
            shutil.copy(path, f"{path}.backup_{timestamp}")
            print(f"기존 {path} → {path}.backup_{timestamp} 로 백업 완료")
        except FileNotFoundError:
            pass  # 기존 파일이 없으면 백업 생략

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VEC_PATH)
    print(f"\n새 {MODEL_PATH}, {VEC_PATH} 저장 완료!")


if __name__ == "__main__":
    merged = load_and_merge()
    model, vectorizer = train(merged)
    sanity_check(model, vectorizer)
    save_with_backup(model, vectorizer)
    print("\n재학습 끝! main.py / test_input.py를 다시 실행해서 확인해보세요.")
