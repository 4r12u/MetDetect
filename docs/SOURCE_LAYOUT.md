# Bố trí source theo bốn phase — 1.2.1

workflow.py nhận output directory hoặc marker JSON của phase trước; estimators.py xử lý lựa chọn model từ --model/--models và kết hợp training config trước khi tính trial budget. README và SETUP_WINDOWS.md chứa lệnh hiện hành. Phase 2–4 không cần truyền lại Dataset.

Phase 4 bổ sung estimators.py (registry, train config, binary score, native Top Feature), experiments.py (trial/tuning, lưu bundle riêng, đánh giá test riêng). model.py giữ luồng legacy và scan tương thích, đã hỗ trợ score decision/threshold. reporting.py/report.html tổng hợp xếp hạng theo metric, feature, FP/FN và trial. --evaluate hiện chỉ train/validation; --test chạy riêng. Xem README và docs/TRAINING_CONFIG.md. Bố trí baseline bên dưới giữ để tra cứu các module Phase 1–3.

Giao diện hiện hành: --extraction PATH → --analysis PATH → --preprocessing PATH → --evaluate PATH. Dùng cùng PATH. --metric/--visual đọc kết quả đã có; lệnh cụ thể ở README root. Các subcommand bên dưới vẫn hỗ trợ tương thích.

Các file bổ sung:

| File | Trách nhiệm |
| --- | --- |
| workflow.py | Nhận flag, tự chọn manifest/artifact, tìm dataset đệ quy, tạo outputs/<run> và nối các phase |
| phase3_preprocessing/artifacts.py | Lưu encoder.joblib, X_*.npz, splits.csv, preprocessing.json; kiểm tra nguồn/checksum khi Phase 4 dùng lại |
| reporting.py | Tổng kết metric/JSON, kiểm tra kết quả cũ, ghi báo cáo HTML |
| report.html | Template HTML offline, lọc/tìm kiếm sample, so sánh model và confusion matrix |

Phase 3 fit trên train hoặc chỉ transform bằng --bundle. Phase 4 đọc artifact Phase 3 đã lưu, không fit lại. --evaluate có nhãn train/test sẽ train/chọn bằng validation rồi đánh giá test; --bundle chỉ predict. --metric lưu outputs/<run>/metrics.json; --visual ghi visual/<run>/index.html. Báo cáo flag chỉ công nhận Phase 4 hoàn tất qua flag; không tái sử dụng metric chưa xác minh từ run subcommand cũ.

~~~text
pypi_metadata_detector/
├── phase1_metadata_extraction/
│   ├── __init__.py
│   └── extract.py
├── phase2_metadata_analysis/
│   ├── __init__.py
│   ├── reference.py
│   └── signals.py
├── phase3_preprocessing/
│   ├── __init__.py
│   ├── dataset.py
│   └── preprocess.py
├── phase4_ml_classification/
│   ├── __init__.py
│   └── model.py
├── __init__.py
├── __main__.py
├── cli.py
├── common.py
└── preprocess.py
~~~

## File và trách nhiệm

| Phase | File | Trách nhiệm |
| --- | --- | --- |
| 1. Extraction | [extract.py](../pypi_metadata_detector/phase1_metadata_extraction/extract.py) | Đọc file/folder/archive, chọn PKG-INFO/METADATA, parse header/body, ghi metadata và status |
| 2. Analysis | [reference.py](../pypi_metadata_detector/phase2_metadata_analysis/reference.py) | Snapshot PyPI official, target list, exact-release lookup và reference checksum |
| 2. Analysis | [signals.py](../pypi_metadata_detector/phase2_metadata_analysis/signals.py) | Trạng thái trường, tín hiệu tên, registry comparison và feature thô |
| 3. Preprocessing | [dataset.py](../pypi_metadata_detector/phase3_preprocessing/dataset.py) | Kiểm tra dữ liệu/nhãn, chọn sample đủ điều kiện, chia train/validation/test theo package group |
| 3. Preprocessing | [preprocess.py](../pypi_metadata_detector/phase3_preprocessing/preprocess.py) | FeatureEncoder: numeric/TF-IDF, fit train-only; prepare_training tạo các ma trận cho Phase 4 |
| 4. ML | [model.py](../pypi_metadata_detector/phase4_ml_classification/model.py) | RF/DT, validation selection, bundle, đánh giá và dự đoán; gọi Phase 3 để chuẩn bị X |

## Phần dùng chung

- cli.py điều phối command và nối các phase, không chứa thuật toán feature/model.
- common.py chứa config, IO JSON/CSV, sample discovery, hashing và progress.
- __main__.py / __init__.py là entry point/version.
- preprocess.py ở root chỉ có import chuyển tiếp FeatureEncoder để đọc joblib đã lưu bởi bản 1.0.0. Toàn bộ xử lý preprocessing nằm trong thư mục Phase 3; không có hai implementation.
- Config, dataset, references, outputs và tests tiếp tục ở root project. Không chuyển dữ liệu mẫu vào source.

## Luồng gọi

- extract: CLI → Phase 1.
- reference: CLI → Phase 2/reference.
- analyze: CLI → Phase 2/signals.
- train: CLI → Phase 4 điều phối → Phase 3 kiểm tra/split/fit-transform → Phase 4 train và chọn model.
- evaluate: CLI → Phase 4 → Phase 3 load/transform; không fit.
- scan: CLI → Phase 1 → Phase 2 → Phase 3 transform → Phase 4 predict.

Giữ nguyên namespace python -m pypi_metadata_detector, tên lệnh, config, feature schema, output schema và semantics của model. Model/checkpoint cũ không cần tạo lại chỉ vì đổi thư mục.
