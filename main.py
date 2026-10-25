# -*- coding: utf-8 -*-
import io
import sys
import os
import time
import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from url_checker import check_message_urls, strip_urls_for_ml

# 윈도우 터미널 UTF-8 출력 보정 (콘솔 실행 시 한글 깨짐 방지)
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding="utf-8")

app = FastAPI(title="스미싱 실시간 하이브리드 탐지 API")

# 프론트엔드(index.html)가 다른 주소/포트(Live Server 등)에서 열려도
# fetch 요청이 막히지 않도록 CORS 허용.
# 개발 단계라 전체 허용(*)으로 두고, 배포 시에는 실제 프론트 주소로 좁히는 걸 권장.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. 머신러닝 모델 로드 (서버 시작할 때 딱 한 번만 로드)
MODEL_PATH = "model.pkl"
VEC_PATH = "vectorizer.pkl"

ml_available = False
model = None
vectorizer = None

if os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VEC_PATH)
        ml_available = True
        print("[정보] 모델 로드 완료")
    except Exception as e:
        print(f"[경고] 모델 로드 실패: {e}")
else:
    print("[경고] model.pkl 또는 vectorizer.pkl 파일을 찾을 수 없습니다.")


# 요청 body 형식 정의: {"message": "문자 내용"}
class MessageRequest(BaseModel):
    message: str


@app.get("/")
def root():
    """서버가 살아있는지 확인용 (Postman GET 테스트에 사용)"""
    return {
        "status": "ok",
        "message": "스미싱 탐지 서버가 정상적으로 실행 중입니다.",
        "model_loaded": ml_available,
    }


@app.post("/diagnose")
def diagnose(req: MessageRequest):
    """문자 메시지 하나를 받아서 스미싱 위험도를 진단"""
    start_time = time.perf_counter()  # 처리 시작 시각 기록 (UX 성능 측정용)

    msg = req.message.strip()

    if not msg:
        return {"error": "message가 비어 있습니다."}

    # 1) 머신러닝 텍스트 분석
    # 재학습된 모델은 'URL이 제거된 문구'로 학습됐으므로, 예측할 때도 반드시 동일하게
    # URL을 지운 텍스트를 넣어야 함 (URL 위험도는 바로 아래 2번 단계가 따로 판단).
    ml_prob = 0.0
    if ml_available:
        text_for_ml = strip_urls_for_ml(msg)
        vec_text = vectorizer.transform([text_for_ml])
        ml_prob = round(model.predict_proba(vec_text)[0][1] * 100, 1)

    # 2) URL 보안 분석
    url_res = check_message_urls(msg)
    url_score = url_res.get("max_risk_score", 0)
    has_url = url_res.get("has_url", False)
    url_details = url_res.get("results", [])

    # 2-1) "검증된 안전 URL" 여부 판단
    # - URL이 포함돼 있고
    # - 자체 규칙 점수(url_score)가 0점이고
    # - 포함된 모든 URL이 VirusTotal에서 malicious=0, suspicious=0으로 확인된 경우
    # → ML 텍스트 모델이 단독으로 "위험" 판정을 내리지 못하도록 상한선을 둔다.
    # (ML 모델이 "URL 존재 여부" 자체에 과민 반응해 정상 URL까지 오탐하는 경향이 있어 추가한 안전장치)
    # 참고: model.pkl 재학습(10/25) 이후 URL 유무에 대한 과의존 문제는 근본적으로 해결됐지만,
    # 혹시 모를 경우를 대비해 이 안전장치는 그대로 유지한다.
    url_verified_safe = False
    if has_url and url_score == 0 and url_details:
        url_verified_safe = all(
            item.get("virustotal") is not None
            and item["virustotal"]["malicious"] == 0
            and item["virustotal"]["suspicious"] == 0
            for item in url_details
        )

    # 3) 하이브리드 종합 진단 (test_input.py와 동일한 임계값 기준)
    if url_verified_safe:
        # URL은 VirusTotal로 안전이 확인됐으므로, 텍스트 모델 단독 판단으로는 "위험"까지 올리지 않음
        if ml_prob >= 70:
            verdict = "주의"
            verdict_detail = (
                "포함된 URL은 VirusTotal 등으로 안전이 확인됐으나, "
                "문구 패턴이 스미싱과 유사하여 참고용으로 주의 표시"
            )
        elif ml_prob >= 35:
            verdict = "주의"
            verdict_detail = "확인되지 않은 의심 키워드 포함 (URL은 안전 확인됨)"
        else:
            verdict = "안전"
            verdict_detail = "정상 문자메시지로 판단됨 (URL 안전 확인됨)"
    elif url_score >= 50 or ml_prob >= 70:
        verdict = "위험"
        verdict_detail = "스미싱 의심 (즉시 삭제 및 링크 클릭 금지)"
    elif url_score >= 20 or ml_prob >= 35:
        verdict = "주의"
        verdict_detail = "확인되지 않은 외부 링크 또는 의심 키워드 포함"
    else:
        verdict = "안전"
        verdict_detail = "정상 문자메시지로 판단됨"

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)  # 처리 소요 시간(ms)

    return {
        "message": msg,
        "ml_probability": ml_prob,       # 텍스트 기반 스미싱 확률 (%)
        "url_score": url_score,          # URL 위험도 점수 (0~100)
        "has_url": has_url,
        "url_details": url_details,      # 개별 URL별 원본 URL + 위험 요인
        "url_verified_safe": url_verified_safe,  # VirusTotal로 안전 검증된 URL인지 여부
        "verdict": verdict,              # 위험 / 주의 / 안전
        "verdict_detail": verdict_detail,
        "response_time_ms": elapsed_ms,  # 진단 처리에 걸린 시간 (교수님 피드백: UX 성능 지표)
    }
