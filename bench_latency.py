# -*- coding: utf-8 -*-
"""
응답 시간 벤치마크 (PPT 14페이지 '응답 시간 측정' 항목용)

사용법
  1) 서버 실행 (캐시 없는 순수 성능을 보려면 캐시를 끄고 실행)
       PowerShell:  $env:URL_CACHE_TTL=0; $env:VIRUSTOTAL_API_KEY="키"; uvicorn main_hybrid:app --port 8001
     캐시 효과까지 보려면 URL_CACHE_TTL 을 지정하지 않고 실행 (기본 600초)
  2) python bench_latency.py --base http://127.0.0.1:8001 --repeat 10
     Render 서버:         python bench_latency.py --base https://smishing-detector-91tv.onrender.com --repeat 10
결과: 콘솔 표 + bench_result.csv(원본 측정값)
  client_ms = 요청 보내고 응답 받을 때까지(end-to-end, 네트워크 왕복 포함)
  server_ms = 서버가 보고한 처리 시간(response_time_ms)
※ 외부 조회 케이스는 VirusTotal 무료 키(분당 4회)에선 429 가 날 수 있으니 --repeat 를 낮추거나 유료 키를 쓰세요.
"""
import argparse, csv, statistics, time
import requests

CASES = {
    "링크없음": [
        "[Web발신] 인증번호 [482913]를 입력해주세요.",
        "엄마 나 지금 폰 고장나서 문자해. 카톡 ID 알려줄게 급해",
    ],
    "내부-공식도메인": [
        "[한진택배] 고객님의 상품이 내일 배송될 예정입니다. 배송조회 https://www.hanjin.com",
        "[CJ대한통운] 택배가 오늘 오후 배송됩니다. https://www.cjlogistics.com",
        "[국민은행] 보안 안내 https://www.kbstar.com",
    ],
    "내부-정적고위험(IP/apk)": [
        "[국제발신] 해외직구 승인 안내: http://192.168.1.100:8080/check.apk",
        "택배 확인 http://203.0.113.7/app.apk",
    ],
    "외부-일반도메인": [
        "행사 안내 https://www.python.org/about/",
        "자료 확인 https://www.wikipedia.org/",
        "이벤트 https://www.mozilla.org/ko/",
    ],
    "외부-단축URL": [
        "[Web발신] 택배 도착 안내 확인하세요 bit.ly/3xYzQ12",
        "고객님 앞으로 중요 문서가 도착했습니다 https://han.gl/aQ7Zp",
        "[안내] 미수령 택배 확인 vo.la/Wm5dX",
    ],
}


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8001")
    ap.add_argument("--repeat", type=int, default=10)
    ap.add_argument("--fast", action="store_true", help="?fast=true (외부 조회 없는 1차 판정) 측정")
    ap.add_argument("--out", default="bench_result.csv")
    a = ap.parse_args()

    s = requests.Session()
    print("워밍업(콜드스타트 제외)...")
    for _ in range(3):
        try:
            s.get(a.base + "/", timeout=90)
        except requests.RequestException as e:
            print("  서버 연결 실패:", e); return

    rows = []
    for case, msgs in CASES.items():
        for _ in range(a.repeat):
            for m in msgs:
                t = time.perf_counter()
                r = s.post(a.base + "/diagnose", params={"fast": str(a.fast).lower()}, json={"message": m}, timeout=30)
                client = (time.perf_counter() - t) * 1000
                d = r.json()
                rows.append({"case": case, "client_ms": round(client, 1), "server_ms": d.get("response_time_ms"),
                             "verdict": d.get("verdict"), "status": r.status_code,
                             "timed_out": any(u.get("timed_out") for u in d.get("url_details", [])),
                             "message": m[:40]})

    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)

    print(f"\n{'케이스':<22}{'n':>4}  {'server p50':>10}{'p95':>8}  {'client p50':>10}{'p95':>8}{'p99':>8}{'max':>8}  timeout")
    for case in CASES:
        rs = [r for r in rows if r["case"] == case]
        sv, cl = [r["server_ms"] for r in rs], [r["client_ms"] for r in rs]
        to = sum(r["timed_out"] for r in rs)
        print(f"{case:<22}{len(rs):>4}  {statistics.median(sv):>10.1f}{pct(sv,95):>8.1f}  "
              f"{statistics.median(cl):>10.1f}{pct(cl,95):>8.1f}{pct(cl,99):>8.1f}{max(cl):>8.1f}  {to}")
    allc = [r["client_ms"] for r in rows]
    print(f"\n전체 client p95 = {pct(allc,95):.1f} ms, p99 = {pct(allc,99):.1f} ms  → 상세: {a.out}")


if __name__ == "__main__":
    main()