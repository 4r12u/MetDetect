# Kế hoạch build tool mới — PyPI Metadata Detector

## CLI 1.2.1 — 26/10/2026

Đã chuyển luồng khuyến nghị sang --extraction DATASET --output RUN → --analysis RUN → --preprocessing RUN → --evaluate RUN --model CODE. Có thể dùng JSON marker của bước trước thay cho RUN. CODE hỗ trợ dt/rf/lr/svm/cnb/xgb, danh sách dấu phẩy hoặc all. Setup và lệnh hiện hành nằm trong README.md và SETUP_WINDOWS.md. Các ví dụ dùng Dataset cho Phase 2–4 bên dưới chỉ còn tương thích lịch sử.

## Cập nhật 26/10/2026 — 1.2.0 đã triển khai

Theo yêu cầu mới, model Phase 4 gồm DT/RF/LR/LinearSVC/ComplementNB/XGBoost. --evaluate mặc định train/validation theo --train-config, lưu experiments/<ID> không ghi đè. --evaluate PATH --experiment ID --test đánh giá held-out riêng. --metric/--visual hỗ trợ Top Model theo metric, Top Feature và FP/FN. Không dùng các đoạn RF/DT-only hoặc train-rồi-test của baseline bên dưới làm giao diện hiện hành; xem README.md và MEMBER2_TRAINING.md. Dataset ở ngoài source ZIP, số lượng lấy từ manifest đã kiểm chứng, không khóa số mẫu vào tool.

Chốt ngày 24/10/2026, cập nhật 1.1.0: bốn flag phase độc lập, --metric và --visual tạo báo cáo HTML offline. Dataset hiện có 2.292 artifact với nhãn/split. Source/bộ kiểm thử đã nâng cấp; QA synthetic không là metric thật. Xem IMPLEMENTATION_STATUS.md, SOURCE_LAYOUT.md và README ở root.

Yêu cầu flag/HTML mới nhất thay phần CLI và hạn chế dashboard trong kế hoạch cũ bên dưới: mỗi phase lưu ở outputs, báo cáo HTML ở visual, không dựng web server. Phase 3 lưu encoder/X độc lập; Phase 4 đọc chúng, không fit lại preprocessing. Giữ subcommand cũ để tương thích.

## 1. Mục tiêu và phạm vi

Kế hoạch này thay thế toàn bộ backlog, phase, schema và tiêu chí nghiệm thu của tool static/LLM trước đây. Mục tiêu duy nhất:

**Package/metadata → metadata JSON → tín hiệu metadata và tên → preprocessing → RF/DT → prediction và metric.**

Hoàn thành khi CLI trích metadata, train hai model từ manifest nhãn, đánh giá test riêng và scan sample mới bằng bundle đã lưu. Đây là project môn học ứng dụng ML vào bảo mật; không yêu cầu novelty, RQ, ablation hay vượt trội paper.

Tool mới dùng namespace pypi_metadata_detector ở root. Không chuyển tiếp model/cache/schema/dependencies/CLI cũ. Source cũ đã xóa theo yêu cầu tiếp theo của người dùng.

## 2. Phase 1 — Metadata extraction

**Input:** PKG-INFO/METADATA trực tiếp, folder sample hoặc archive .whl/.zip/.tar.gz. Một artifact/version là một sample; không biến mỗi file metadata trong archive thành một sample.

**Công việc:**

1. Liệt kê sample, xác nhận tổng số đầu vào và hiện progress.
2. Chỉ đọc member metadata, không giải nén toàn package khi không cần; không phân tích source .py.
3. Chọn metadata của chính distribution. Bỏ metadata vendored nếu nhận diện được. Nhiều candidate tương đương được chọn theo quy tắc cố định và lưu sources; candidate khác identity/nội dung không giải quyết được phải ghi metadata_conflict, không ghép tùy tiện.
4. Dùng email.parser để đọc header nhiều dòng/lặp và Description ở phần thân. Regex dùng nhận diện, chuẩn hóa giá trị và các tín hiệu.
5. Giữ giá trị gốc/Unicode; không lấy tên archive thay Name rồi coi là thông tin khai báo.
6. Ghi ok, missing_metadata, invalid_metadata, metadata_conflict hoặc input_error. Thiếu Name/Version không trở thành record hợp lệ để train/scan.

**Các trường:**

| Trường | Kiểu raw |
| --- | --- |
| Metadata-Version, Name, Version | string hoặc null nếu không tồn tại |
| Summary, Home-page, Author, Author-email | string hoặc null |
| License, License-Expression, Requires-Python | string hoặc null |
| Description | string hoặc null |
| Project-URL, Requires-Dist | list[string], giữ đủ lần xuất hiện |

Metadata-Version là version định dạng của package; schema_version là version JSON riêng của tool. Version luôn là chuỗi. Chuỗi UNKNOWN/None nguyên văn không bị xóa ở Phase 1. Không nhân đôi Description dài ở nhiều vị trí trong JSON.

Output mỗi sample: metadata.json và status.json. Contract minh họa:

~~~json
{
  "schema_version": "metadata-1",
  "sample_id": "sample_001",
  "source": {
    "input": "packages/example-0.1.tar.gz",
    "metadata_member": "example-0.1/PKG-INFO"
  },
  "metadata": {
    "Metadata-Version": "2.1",
    "Name": "example",
    "Version": "0.1",
    "Summary": "Example package",
    "Home-page": "UNKNOWN",
    "Author": null,
    "Author-email": null,
    "License": "UNKNOWN",
    "Description": "Example description",
    "Project-URL": [],
    "Requires-Dist": []
  }
}
~~~

Đây là ví dụ minh họa, không phải sample thật. Header mở rộng có thể lưu raw_headers dạng tên → danh sách giá trị, không lặp lại body. Label, split và group giữ ở manifest/index, không trộn vào metadata hoặc X.

## 3. Phase 2 — Metadata analysis và feature generation

### 3.1. Trạng thái trường

- Phân biệt missing, empty, placeholder, present.
- Placeholder theo tập giá trị cấu hình tường minh sau trim/casefold: UNKNOWN, None, N/A. JSON null là missing; chuỗi "None" là placeholder.
- Trường lặp xử lý từng phần tử, không ép list thành string giả.
- License xét cùng License-Expression; URL dự án xét Home-page và Project-URL.
- Lưu trạng thái, lý do và giá trị raw để đối chiếu.

### 3.2. Snapshot và đối chiếu PyPI

- Lệnh sync riêng lấy PyPI Simple JSON Index làm inventory tên, ghi URL nguồn, ngày UTC, serial nếu có và hash snapshot.
- Tập metadata chọn lọc phải theo đúng name/version. Không gọi API toàn PyPI để có một demo.
- Analyze/train/scan chạy offline bằng snapshot đã chốt; không sync ngầm.
- Author/email chỉ là dữ liệu khai báo, không xác thực publisher.
- Kết quả so sánh: match, mismatch, unavailable hoặc lookup_error. Thiếu snapshot cùng version không được so với latest rồi kết luận giả mạo.
- Không tự truy cập Home-page/Project-URL hoặc lệnh trong sample.
- Danh sách đăng ký không là danh sách benign.
- 404/removed/lỗi mạng là audit, không là nhãn hoặc feature ML mặc định: tránh học việc malware đã bị takedown.
- Name/version/author mismatch giữ ở audit bản đầu. Chỉ thêm vào X sau khi chốt định nghĩa và có snapshot phù hợp thời điểm.

### 3.3. Tín hiệu typosquatting

- Chuẩn hóa lowercase và gom chuỗi dấu . _ - thành dấu -, theo PyPA.
- Tra exact membership trong inventory. Tên bằng nhau sau chuẩn hóa không là typo.
- reference_targets.csv là tập tên mục tiêu nhỏ, chọn trước từ nguồn giải thích được. Target không thay nhãn benign của dataset.
- Tính nearest-target edit distance và sáu cờ: repeated_character, omitted_character, swapped_adjacent_character, swapped_words, keyboard_or_visual_substitution, version_suffix.
- Exact target: ghi matched_target, typo=false; không tìm tên khác để ép sinh cảnh báo.
- Ngưỡng distance 1/2 cấu hình hoặc chọn trên validation. Không dùng test để chọn ngưỡng hay target.
- Không fuzzy-match mỗi sample với toàn inventory; chỉ so tập target đã chọn. RapidFuzz là lựa chọn tăng tốc nếu cần.
- Nearest target lưu cho giải thích; danh tính target không là categorical feature mặc định.
- Thiếu popularity thì mô tả là "tín hiệu tên kế thừa từ SpellBound", không tuyên bố tái hiện toàn bộ phương pháp.
- Cảnh báo tên gần giống tách khỏi prediction malicious/benign.

### 3.4. Đặc điểm chuỗi người dùng đề xuất

Giữ thành profile lexical_experiment, mặc định false, triển khai sau baseline:

- Chỉ tính phép đo có định nghĩa rõ, chẳng hạn Shannon entropy và tỷ lệ nhóm ký tự theo từng trường được chọn; xử lý missing/chuỗi rỗng nhất quán.
- Không đặt tên kết quả là "obfuscation detected"; URL, tên người, văn bản đa ngôn ngữ có thể khác biệt tự nhiên.
- Không dùng điểm password-strength làm xác suất malicious hoặc tự gán nhãn bằng ngưỡng.
- Feature profile có version và lưu trong bundle; train/scan dùng cùng định nghĩa.
- Nhóm thử nghiệm này không chặn hoàn thành demo đầu tiên.

**Output Phase 2:** signals.json mỗi sample, audit đối chiếu, feature table số/nhị phân. Liệt kê unknown là mô tả; classifier học từ feature và nhãn thật.

## 4. Phase 3 — Preprocessing

**Baseline:**

| Nhóm | Biểu diễn |
| --- | --- |
| Metadata | Cờ missing/empty/placeholder theo từng trường đã chọn |
| Tên | Nearest-target edit distance và sáu cờ biến đổi; quy định rõ exact/no-target |
| Văn bản | TF-IDF từ Summary + Description; word ngram (1,2), max_features cấu hình, mức đầu 3.000 |
| Chuỗi thử nghiệm | Chỉ khi profile riêng được bật và lưu trong bundle |

Không đưa vào X mặc định: ID/path/filename, Name/Version raw, author/email/domain/URL raw, label/split/group, nearest_target identity, lỗi parser/API, HTTP status và ngày sync.

**Thứ tự xử lý train:**

1. Validate manifest, nhãn và eligibility từ Phase 1/2.
2. Group theo normalized package Name; các phiên bản cùng package không qua nhiều split.
3. Phát hiện bản sao metadata/nhãn mâu thuẫn; không để bản sao qua train/test hoặc tự sửa nhãn.
4. Có split thì kiểm tra overlap. Chưa có thì tạo khoảng 70/15/15, seed=42, cố gắng giữ phân bố lớp theo group và lưu splits.csv. Không đủ group/lớp phải báo rõ.
5. Split trước khi fit TF-IDF/imputer/transformer. Chỉ fit trên train; validation/test dùng transform.
6. Ghép numeric/boolean và TF-IDF thành X sparse, giữ feature names và row/sample mapping.

Scan dùng preprocessing đã fit; không fit lại vocabulary hay thay reference ngầm.

**Output:** eligibility/splits, feature schema, row mapping, fitted preprocessing và X. Không cần HTML graph hoặc hệ thống checkpoint phức tạp.

## 5. Phase 4 — ML classification và evaluation

- Bắt buộc RF và DT, cùng X/split; không bắt đầu bằng tuning lớn.
- Chọn model bằng F1 lớp malicious trên validation. Test dùng sau khi chốt model/threshold.
- Báo precision/recall/F1 từng lớp, confusion matrix, số sample đủ điều kiện và sample bị loại theo lý do.
- Không báo metric fixture giả lập như hiệu quả thật.
- Score chỉ xuất khi model hỗ trợ và classes mapping đúng; không gọi score chưa calibration là độ chắc chắn.
- Bundle lưu fitted preprocessing, hai model, model được chọn, class mapping, config/feature version, reference hash, manifest/split identity và phiên bản môi trường.
- Chỉ load bundle local do nhóm tạo/tin cậy; không deserialize model tải từ nguồn lạ.
- Scan không yêu cầu nhãn; prediction và true label nếu có nằm riêng.
- Metadata không xử lý được hoặc bundle/reference không tương thích thì báo lỗi/không dự đoán; không điền benign.
- Chỉ báo metric typosquatting khi có annotation cho typosquat/target; nhãn malware không thay annotation đó.

## 6. Cấu trúc source, dataset và output

~~~text
project-root/
  pyproject.toml
  README.md
  pypi_metadata_detector/
    __init__.py
    __main__.py
    cli.py
    common.py
    preprocess.py  # chỉ import tương thích cho bundle 1.0.0
    phase1_metadata_extraction/
      __init__.py
      extract.py
    phase2_metadata_analysis/
      __init__.py
      reference.py
      signals.py
    phase3_preprocessing/
      __init__.py
      dataset.py
      preprocess.py
    phase4_ml_classification/
      __init__.py
      model.py
  configs/default.json
  data/manifest.csv
  references/
    reference.json
  tests/
~~~

Source chia bốn phase theo SOURCE_LAYOUT.md; reporting/IO dùng common.py, không cần module report.py riêng. Phase 3 sở hữu eligibility, group split và vector hóa; Phase 4 gọi Phase 3 rồi train/evaluate/predict. Inventory, targets, release metadata và provenance chung trong reference.json. Không thêm provider/plugin/agent orchestration.

Manifest tối thiểu:

~~~csv
sample_id,path,label
sample_001,samples/sample_001/PKG-INFO,benign
sample_002,samples/sample_002/METADATA,malicious
~~~

Path tương đối với manifest, sample_id duy nhất. Luồng scan nhận input trực tiếp hoặc manifest không label. Nguồn dataset/nhãn ghi ở data/README.md. Không khóa vào V1 1.000 mẫu hoặc mini 200; không tự giữ split cũ nếu sai grouping.

~~~text
outputs/<run>/
  samples/<sample_id>/metadata.json
  samples/<sample_id>/signals.json
  samples/<sample_id>/status.json
  features.csv
  splits.csv
  bundle.joblib
  validation_metrics.json
  test_metrics.json
  predictions.csv
  run_summary.json
~~~

Chỉ tạo output cho công đoạn thực sự chạy. Extraction không sinh metric/bundle rỗng để giả hoàn thành. Summary có total/ok/partial/skipped/failed và lý do, tổng trạng thái bằng total.

## 7. CLI và progress dự kiến

Các lệnh này đã có trong source hiện hành; README ở root là hướng dẫn chạy thực tế.

| Lệnh | Chức năng |
| --- | --- |
| reference sync | Lấy/cache official inventory và metadata chọn lọc, lưu snapshot |
| extract | Phase 1 cho input/manifest |
| analyze | Phase 2 từ extraction và snapshot |
| train | Tạo/kiểm tra split, fit preprocessing trên train, train RF/DT và chọn bằng validation |
| evaluate | Đánh giá bundle đã chốt trên split được chỉ định, không fit |
| scan | Phase 1 → 2 → transform → predict bằng fitted bundle |

Ví dụ chạy tại root bản test sau khi triển khai và cài tool của nhóm; venv đã kích hoạt:

~~~powershell
python -m pip install -e .
python -m pypi_metadata_detector reference sync --output .\references
python -m pypi_metadata_detector extract --manifest .\data\manifest.csv --output .\outputs\metadata-run
python -m pypi_metadata_detector analyze --run .\outputs\metadata-run --references .\references
python -m pypi_metadata_detector train --run .\outputs\metadata-run --manifest .\data\manifest.csv
python -m pypi_metadata_detector evaluate --run .\outputs\metadata-run --bundle .\outputs\metadata-run\bundle.joblib --split test
python -m pypi_metadata_detector scan --input .\mini_200_mixed --bundle .\outputs\metadata-run\bundle.joblib --references .\references --output .\outputs\metadata-scan
~~~

Install chỉ áp dụng tool của nhóm, không là package mẫu. Train không tự gọi mạng hoặc quay lại pipeline cũ.

Progress bắt buộc dễ đọc từ bản đầu:

~~~text
Phase 1 | Xác minh đầu vào: 200 sample
[1/200] Package: example | Phase: 1 | Status: OK | Time: 0.1s
Phase 1 hoàn thành | OK: 195 | Partial: 0 | Skipped: 3 | Failed: 2
Phase 2 | Reference: <snapshot-id> | Targets: <n>
[1/195] Package: example | Phase: 2 | Status: OK | Typosquat: no | Time: 0.0s
Phase 3 | Train: <n> | Validation: <n> | Test: <n> | Features: <n>
Phase 4 | Model: Random Forest | Status: TRAINING
Phase 4 | Model: Decision Tree | Status: COMPLETE
~~~

Số trên chỉ minh họa, không là kết quả thật. Console dễ đọc; JSON/CSV để lưu. Một input lỗi không khiến cả batch thành cùng một kết luận.

## 8. Thứ tự build

| Mốc | Việc xây | Điều kiện xong |
| --- | --- | --- |
| M0 | Package độc lập, config nhỏ, schema metadata/signals, fixture synthetic | Import và CLI help chạy; chưa công bố metric thật |
| M1 | Parser, direct/folder/archive input, candidate selection, progress | Metadata folded/repeated/Unicode đúng; mỗi sample có output/status |
| M2 | Snapshot, target CSV, placeholder flags, sáu name signals, đối chiếu chọn lọc | Analyze offline; exact normalized name không cảnh báo; lookup error không thành nhãn |
| M3 | Group split, TF-IDF train-only, RF/DT, validation, bundle, evaluate/scan | End-to-end fixture chạy; save/load ổn định; evaluate/scan không fit |
| M4 | Pilot metadata thực, batch, kiểm tra nguồn nhãn, demo và hướng dẫn ngắn | Metric thực đúng dữ liệu; demo scan sample mới |
| Sau baseline | Profile đặc điểm chuỗi người dùng đề xuất | Không chặn M4; chỉ bật khi feature được định nghĩa/chốt |

Làm M0 → M4 tuần tự. Nếu dataset/nhãn sẵn sàng, mục tiêu baseline là một buổi; thời gian thu thập/kiểm tra nhãn hoặc registry lịch sử tính riêng. Không xây dashboard, graph, thêm model hoặc tương thích tool cũ trong bản đầu.

## 9. Kiểm thử cần thiết

1. Header folded/repeated, Description body, Unicode, null khác chuỗi None/UNKNOWN; License-Expression/Project-URL.
2. Metadata trực tiếp, wheel/sdist, candidate conflict/vendored, archive lỗi/thiếu metadata; không thực thi sample.
3. Chuẩn hóa tên, exact-target, fixture sáu signal và cặp không khớp.
4. Offline/snapshot thiếu, version/author comparison, lookup error; đúng trạng thái và không gán nhãn.
5. Không group overlap/metadata duplicate qua train-test; TF-IDF không học token chỉ có ở test.
6. Save/load bundle, classes mapping, reference/config mismatch, evaluate/scan không fit.
7. End-to-end fixture nhỏ, RF/DT, scan không nhãn và batch có input lỗi; totals đúng.

Test chỉ cho hành vi dễ sai hoặc ảnh hưởng dữ liệu/đánh giá; không yêu cầu coverage hình thức hoặc test lặp implementation.

## 10. Đọc sample và chạy mạng

Đọc archive theo member; giới hạn số member và dung lượng metadata giải nén thực tế; từ chối symlink/path traversal. Không gọi shell tar/zip với input người dùng. Không cài/build/import/chạy package, setup.py, lệnh README hoặc dependency/payload.

Regex cố định, có giới hạn input; không nhận regex tùy ý từ metadata. Sync chỉ HTTPS official PyPI với timeout, giới hạn response/cache; không theo URL do sample khai báo. Popularity nếu bổ sung dùng nguồn riêng đã chốt.

Output dùng sample_id an toàn, không ghi đè chỉ vì Name giống nhau. Không load model tùy ý từ network.

## 11. Tiêu chí nghiệm thu và case study

- Extraction batch xuất JSON có thể đối chiếu với metadata gốc.
- Analyze liệt kê trường thiếu/placeholder, lý do tương đồng tên và audit registry.
- Có bảng feature rõ nguồn mỗi cột, NLP TF-IDF fit train-only.
- RF/DT train và chọn bằng validation; metric test riêng.
- Scan offline bằng fitted bundle, không cần label và không thay preprocessing.
- Console rõ tiến trình, summary phân biệt hoàn tất/partial/bỏ qua/lỗi.
- Demo tên bình thường, tên gần target, metadata thiếu và input lỗi. Fixture được ghi rõ synthetic; không gọi package ngoài đời là malware chỉ vì demo.
- Case study trình bày bài toán, nguồn dữ liệu/nhãn, phương pháp, cách chạy, kết quả và giới hạn. Không thêm nghĩa vụ novelty/ablation.
- Ý tưởng kiểm tra README/source người dùng nêu được giữ là mở rộng để xem xét sau, không là công việc hiện tại.

## 12. Dẫn chứng phương pháp

- [MeMPtec, WWW 2024](https://arxiv.org/pdf/2402.07444): metadata feature engineering + classifier. Thực nghiệm npm, có feature ngoài artifact; chỉ kế thừa phần phù hợp.
- [Typosquatting and Combosquatting Attacks on the Python Ecosystem, 2020](https://conferences.computer.org/eurosp/pdfs/EuroSPW2020-7k9FlVRX4z43j4uE2SeXU0/859700a508/859700a508.pdf): name comparison/edit distance tìm candidate, không tự chứng minh malware.
- [SpellBound, bản arXiv 2020](https://arxiv.org/pdf/2003.03471): sáu nhóm tín hiệu tên + popularity. Bản đầu chưa tái hiện popularity.
- [PyPA Core Metadata](https://packaging.python.org/en/latest/specifications/core-metadata/): định dạng các trường.
- [PyPA Name Normalization](https://packaging.python.org/en/latest/specifications/name-normalization/): chuẩn hóa tên.
- [PyPI Index API](https://docs.pypi.org/api/index-api/): name inventory.
- [PyPI JSON API](https://docs.pypi.org/api/json/): metadata project/release.
- [PyPI BigQuery](https://docs.pypi.org/api/bigquery/): dữ liệu lớn/popularity, không bắt buộc cho demo.
- [scikit-learn text features](https://scikit-learn.org/stable/modules/feature_extraction.html): TF-IDF là lựa chọn NLP của project, không tự gán cho ba paper.

## 13. Hủy hiệu lực kế hoạch cũ

Các yêu cầu phân tích toàn bộ .py, Scalpel/AST, LLM provider/skill/refinement, CodeQL, taxonomy hành vi, KG/GNN, CodeBERT, XGBoost/LR, semantic dictionary, static invariant, HTML graph, dataset V1 cố định và milestone cũ hết hiệu lực.

Không lấy test pass hoặc metric của tool cũ làm bằng chứng tool mới. Tài liệu nguyên bản ở [snapshot lịch sử](history/pre-metadata-20261024/HISTORY.md). Theo yêu cầu tiếp theo, source cũ đã xóa/gỡ; dataset giữ nguyên. Report/ảnh/citation không bị chỉnh sửa.

