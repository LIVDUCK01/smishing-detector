# data_prep — 스미싱 데이터셋 구축·학습 스크립트

## 데이터 흐름 (위에서 아래 순서로 실행했음)
| 단계 | 스크립트 | 입력 → 출력 |
|---|---|---|
| 1 | build_dataset.py | 원본 2개(GitHub, HuggingFace) → dataset_v2.csv, review_needed.csv |
| 2 | apply_review.py | review_needed(검수 결과) → dataset_v2_reviewed.csv, review_audit.csv |
| 3 | relabel_policy.py | dataset_v2_reviewed.csv → dataset_v2_final.csv, policy_changes.csv |
| 4 | make_synthetic_normal.py | dataset_v2_final.csv → synthetic_normal.csv, dataset_v3.csv |
| 5 | make_eval_set.py | dataset_v3.csv → eval_set.csv (학습에 쓰지 않는 평가셋) |
| 6 | train_model.py | dataset_v3.csv, eval_set.csv → model.pkl, vectorizer.pkl |

## 라벨 기준
- 0 정상: 실제 서비스가 보낸 정상 알림·일상 대화
- 1 스팸: 도박·성인·구인·월변·카톡 유도 등 사칭 없는 광고
- 2 스미싱: 택배·은행·기관·가족 등을 사칭해 링크·번호로 유도 (마스킹/난독화 여부와 무관)
- 대출 광고 정책: 기본은 스미싱(2)으로 분류 (`--loan_policy`로 변경 가능)

## 학습 (프로젝트 루트에서 실행. 루트의 train_model.py 와 이름이 겹치니 train_model_v3.py 로 복사해서 사용)
    python train_model_v3.py --data data_prep\dataset_v3.csv --eval data_prep\eval_set.csv --compare
    python train_model_v3.py --data data_prep\dataset_v3.csv --eval data_prep\eval_set.csv --save

## 주의
- synthetic_normal.csv 는 직접 작성한 합성 데이터. 학습(train)에만 사용, 평가에는 사용하지 않는다.
- eval_set.csv 의 악성 도메인은 모두 가상. 실제 접속 대상이 아니다.
- model.pkl 은 사용하는 PC의 scikit-learn 버전으로 직접 학습해서 만들 것.
