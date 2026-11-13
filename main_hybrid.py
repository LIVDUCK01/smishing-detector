# -*- coding: utf-8 -*-
"""
URL 우선 계층형 판정 서버. 기존 main.py 는 건드리지 않고 이 파일로 따로 실행해 비교한다.
    uvicorn main_hybrid:app --port 8000
응답 형식은 main.py 와 같고, link_status / verdict_basis / official_checked 필드가 추가됐다.
"""
import io, os, sys, time, importlib
import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# url_checker.py 가 import 될 때 sys.stdout/stderr 를 detach 해 버려서 uvicorn 로그가 사라지는 문제가 있다.
# 임시 스트림으로 바꿔 둔 채 import 하고 원래 스트림을 되돌린다.
_real_out, _real_err = sys.stdout, sys.stderr
sys.stdout, sys.stderr = io.TextIOWrapper(io.BytesIO(), encoding='utf-8'), io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
try:
    url_checker = importlib.import_module('url_checker')
finally:
    sys.stdout, sys.stderr = _real_out, _real_err

check_message_urls, strip_urls_for_ml = url_checker.check_message_urls, url_checker.strip_urls_for_ml

from hybrid_logic import decide

app = FastAPI(title="스미싱 실시간 하이브리드 탐지 API (URL 우선)")
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=False, 
    allow_methods=["*"], 
    allow_headers=["*"]
)

MODEL_PATH, VEC_PATH = "model.pkl", "vectorizer.pkl"
MAX_LEN = 2000      # 입력 길이 제한(과도한 입력 방지)
ml_available, model, vectorizer, pos_col = False, None, None, 1

if os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH):
    try:
        model, vectorizer = joblib.load(MODEL_PATH), joblib.load(VEC_PATH)
        classes = list(model.classes_)                       # 2분류면 [0,1] → 1열, 3분류면 스미싱(2)의 열
        pos_col = classes.index(2) if len(classes) > 2 else classes.index(1)
        ml_available = True
        print("[정보] 모델 로드 완료")
    except Exception as e:
        print(f"[경고] 모델 로드 실패: {e}")
else:
    print("[경고] model.pkl 또는 vectorizer.pkl 파일을 찾을 수 없습니다.")


class MessageRequest(BaseModel):
    message: str


@app.get("/")
def root():
    return {"status": "ok", "message": "스미싱 탐지 서버(URL 우선 판정)가 실행 중입니다.", "model_loaded": ml_available}


@app.post("/diagnose")
def diagnose(req: MessageRequest, fast: bool = False):
    """fast=true 이면 외부 조회(리다이렉트·VirusTotal) 없이 내부 판정만 반환(수십 ms).
    프론트에서 fast 로 먼저 1차 결과를 보여주고, 이어서 fast=false 로 최종 결과를 갱신하는 2단계 방식에 쓴다."""
    t0 = time.perf_counter()
    msg = req.message.strip()[:MAX_LEN]
    if not msg:
        return {"error": "message가 비어 있습니다."}

    ml_prob = 0.0
    if ml_available:   # 학습 때와 같은 전처리(URL 제거)
        ml_prob = round(model.predict_proba(vectorizer.transform([strip_urls_for_ml(msg)]))[0][pos_col] * 100, 1)
    t1 = time.perf_counter()

    url_res = check_message_urls(msg, network=not fast)
    url_score, has_url, details = url_res.get("max_risk_score", 0), url_res.get("has_url", False), url_res.get("results", [])
    t2 = time.perf_counter()

    d = decide(ml_prob, has_url, url_score, details)
    t3 = time.perf_counter()

    return {
        "message": msg,
        "ml_probability": ml_prob,
        "url_score": url_score,
        "has_url": has_url,
        "url_details": details,                                    # 각 URL의 timing_ms / external_mode 포함
        "url_verified_safe": d["link_status"] in ("official", "verified"),   # 기존 필드 호환
        "link_status": d["link_status"],                       # none / dangerous / suspicious / official / verified / unverified
        "verdict": d["verdict"],                                   # 위험 / 주의 / 안전
        "verdict_basis": d["verdict_basis"],                       # URL / 문구 / URL+문구
        "verdict_detail": d["verdict_detail"],
        "no_link_notice": not has_url,                             # 프론트에서 '링크 없음 — 문구 기준 참고용' 배지 표시용
        "provisional": bool(fast and has_url),                     # 1차(내부) 판정 — 외부 검증 전
        "stage_ms": {                                              # 단계별 서버 처리 시간
            "ml": round((t1 - t0) * 1000, 1),
            "url": round((t2 - t1) * 1000, 1),
            "decide": round((t3 - t2) * 1000, 2),
            "total": round((t3 - t0) * 1000, 1),
        },
        "response_time_ms": round((t3 - t0) * 1000, 2),            # 기존 필드 호환
    }

# 로컬 및 클라우드(Render 등) 동적 포트 바인딩 실행부 추가
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8001))
    uvicorn.run("main_hybrid:app", host="0.0.0.0", port=port, reload=False)
