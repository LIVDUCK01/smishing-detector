# -*- coding: utf-8 -*-
import io
import sys
import os
import joblib
from url_checker import check_message_urls, strip_urls_for_ml

# 윈도우 터미널 UTF-8 출력 보정
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding="utf-8")

# 1. 머신러닝 모델 로드
MODEL_PATH = "model.pkl"
VEC_PATH = "vectorizer.pkl"

ml_available = False
if os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VEC_PATH)
        ml_available = True
    except Exception as e:
        print(f"[경고] 모델 로드 실패: {e}")

print("=" * 65)
print("🛡️  스미싱 실시간 하이브리드 탐지 콘솔")
print("   - 테스트할 문자를 입력하고 엔터를 치세요.")
print("   - 종료하려면 'q' 또는 'exit'를 입력하세요.")
print("=" * 65)

while True:
    try:
        msg = input("\n[문자 입력] > ").strip()
    except (EOFError, KeyboardInterrupt):
        break

    if msg.lower() in ["q", "exit", "종료"]:
        print("\n테스트 콘솔을 종료합니다.")
        break
    if not msg:
        continue

    print("-" * 65)

    # 1) 머신러닝 텍스트 분석
    # 재학습된 모델은 URL이 제거된 문구로 학습됐으므로, 예측 시에도 동일하게 전처리
    ml_prob = 0.0
    if ml_available:
        text_for_ml = strip_urls_for_ml(msg)
        vec_text = vectorizer.transform([text_for_ml])
        ml_prob = model.predict_proba(vec_text)[0][1] * 100
        print(f"📊 [텍스트 분석] AI 스미싱 의심도 : {ml_prob:.1f}%")
    else:
        print("📊 [텍스트 분석] 모델 파일 없음 (URL만 단독 분석)")

    # 2) URL 보안 분석 (키 매핑 수정 완료)
    url_res = check_message_urls(msg)
    url_score = url_res.get("max_risk_score", 0)
    print(f"🔗 [URL 보안분석] 링크 위험도 점수 : {url_score}점 / 100점")

    if url_res.get("has_url"):
        for item in url_res.get("results", []):
            print(f"   - 감지된 URL : {item['original_url']}")
            if item.get("risk_factors"):
                for factor in item["risk_factors"]:
                    print(f"     ⚠️ {factor}")

    # 3) 하이브리드 종합 진단
    print("-" * 65)
    if url_score >= 50 or ml_prob >= 70:
        verdict = "🚨 [위험] 스미싱 의심 (즉시 삭제 및 링크 클릭 금지)"
    elif url_score >= 20 or ml_prob >= 35:
        verdict = "⚠️ [주의] 확인되지 않은 외부 링크 또는 의심 키워드 포함"
    else:
        verdict = "✅ [안전] 정상 문자메시지로 판단됨"

    print(f"👉 종합 진단 결과 : {verdict}")
    print("=" * 65)