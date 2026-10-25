# -*- coding: utf-8 -*-
"""
model.pkl / vectorizer.pkl 이 정확히 뭔지 확인하는 스크립트.
같은 폴더(main.py, model.pkl 있는 곳)에서 실행하세요: python inspect_model.py
"""
import joblib

print("=" * 60)
print("1) 모델 종류 확인")
print("=" * 60)
model = joblib.load("model.pkl")
print(f"모델 클래스: {type(model)}")
print(f"모델 내용: {model}")

# 모델 종류별로 추가 정보 출력
if hasattr(model, "classes_"):
    print(f"클래스(라벨) 종류: {model.classes_}")

if hasattr(model, "n_features_in_"):
    print(f"입력 피처(특징) 개수: {model.n_features_in_}")

# 혹시 Pipeline(여러 단계를 하나로 묶은 것)이라면 내부 단계도 출력
if hasattr(model, "steps"):
    print(f"Pipeline 단계들: {model.steps}")

print()
print("=" * 60)
print("2) 벡터라이저(텍스트→숫자 변환기) 확인")
print("=" * 60)
vectorizer = joblib.load("vectorizer.pkl")
print(f"벡터라이저 클래스: {type(vectorizer)}")

if hasattr(vectorizer, "vocabulary_"):
    vocab = vectorizer.vocabulary_
    print(f"학습된 단어(토큰) 개수: {len(vocab)}")
    print(f"단어 예시 10개: {list(vocab.keys())[:10]}")

print()
print("=" * 60)
print("3) 간단 테스트 — 몇 가지 문장을 직접 넣어서 확률 확인")
print("=" * 60)
test_sentences = [
    "확인용 테스트: http://google.com",
    "안녕하세요 오늘 날씨가 좋네요",
    "[택배] 고객님의 상품이 배송 중입니다. 운송장번호 123456789",
    "[Web발신] 해외직구 결제 완료. 본인 아니면 확인: http://bit.ly/abc123",
]

for sentence in test_sentences:
    vec = vectorizer.transform([sentence])
    prob = model.predict_proba(vec)[0]
    print(f"\n문장: {sentence}")
    print(f"  → 확률 분포: {prob} (보통 [정상확률, 스미싱확률] 순)")
