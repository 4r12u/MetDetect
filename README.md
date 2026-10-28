# PyPI Metadata Detector 1.2.1

Tool metadata-only cho project AIC211: PKG-INFO/METADATA → tín hiệu metadata/tên → TF-IDF và feature số → phân loại benign/malicious. Không thực thi, cài đặt, build hoặc import package mẫu. Không có LLM trong pipeline này.

## Cài tool (môi trường đã kích hoạt)

Chạy tại thư mục gốc bản giải nén (nơi có pyproject.toml), môi trường Python đã kích hoạt. Nếu chưa có môi trường, xem [SETUP_WINDOWS.md](docs/SETUP_WINDOWS.md) trước:

```powershell
python -m pip install -e ".[ml]"
```

`ml` cài thêm XGBoost cho tool. Bỏ `[ml]` nếu chỉ dùng các model scikit-learn. XGBoost thiếu được ghi là trial lỗi, các model khác vẫn chạy. Không cài bất kỳ sample nào trong Dataset.

ZIP source không kèm Dataset, môi trường Python, model hay kết quả cá nhân. Khi chuyển sang thư mục mới, đặt Dataset đã kiểm chứng vào cạnh README này; giữ nguyên cấu trúc archive và manifest. Không cần chuyển sang thư mục source bên trong.

## Chạy bốn phase

```powershell
python -m pypi_metadata_detector --extraction .\Dataset --output .\outputs\run-01
python -m pypi_metadata_detector --analysis .\outputs\run-01
python -m pypi_metadata_detector --preprocessing .\outputs\run-01
python -m pypi_metadata_detector --evaluate .\outputs\run-01 --model all --train-config .\configs\training-default.json --experiment baseline --metric --visual
```

Phase 4 mặc định chỉ train và validation; KHÔNG chạy test. Model: DT, RF, Logistic Regression, Linear SVM, Complement Naive Bayes, XGBoost. Phase 3 fit TF-IDF trên train; Phase 4 dùng lại X/encoder đã lưu. LR/SVM có MaxAbsScaler riêng, fit trên train và lưu cùng model. ComplementNB cần feature không âm; nếu dùng reference rỗng tạo name_distance=-1 hoặc profile có số âm, trial CNB sẽ báo lỗi thay vì tự sửa dữ liệu.

Chỉ Phase 1 đọc dataset/archive/sample/manifest gốc. Phase 2–4 nhận thư mục output của phase trước. Mỗi phase bổ sung artifact vào cùng thư mục run-01, giữ kết quả trước đó; không sao chép cả dataset qua từng phase. Có thể truyền trực tiếp extraction.json cho Phase 2, analysis.json cho Phase 3, preprocessing.json cho Phase 4; phải giữ đủ các file/thư mục liên quan ở cạnh JSON. Sau mỗi phase tool in lệnh bước tiếp. Không đổi --output khi đang đọc một thư mục kết quả. Đường dẫn Dataset kiểu cũ vẫn được hỗ trợ để tương thích, nhưng luồng khuyến nghị là output → output. Phase 1 tự nhận manifest.csv trước dataset.csv; nhãn không được suy từ tên thư mục.

## Chọn model ngay trên lệnh Phase 4

```powershell
python -m pypi_metadata_detector --evaluate .\outputs\run-01 --model dt --experiment dt-01
python -m pypi_metadata_detector --evaluate .\outputs\run-01 --model lr --experiment lr-01
python -m pypi_metadata_detector --evaluate .\outputs\run-01 --model dt,rf,lr --experiment compare-01
```

| Viết tắt | Model |
|---|---|
| dt | Decision Tree |
| rf | Random Forest |
| lr | Logistic Regression |
| svm | Linear SVM |
| cnb | Complement Naive Bayes |
| xgb | XGBoost |
| all | Cả sáu model |

Dùng `--model dt` hoặc `--model=dt`; không gõ `model = dt` thành các từ rời. Nhiều model phân tách bằng dấu phẩy, không có khoảng trắng (hoặc đặt cả chuỗi trong dấu nháy). `--models` là tên tương đương. Bỏ --model thì dùng danh sách model trong --train-config; không có file thì mặc định cả sáu. Nếu kết hợp --model và --train-config, CLI chọn model, file giữ params/grid tương ứng; model chưa khai báo trong file dùng mặc định. --model không dùng cùng --test/--bundle vì model/ngưỡng đã được chốt trong thí nghiệm.

## Tuning và chốt model

```powershell
python -m pypi_metadata_detector --evaluate .\outputs\run-01 --train-config .\configs\training-tuning.json --experiment tuning-01 --metric --visual
```

Mẫu tuning chạy 27 cấu hình, có thử ngưỡng trên validation. Mỗi thí nghiệm phải có ID mới (chữ, số, dấu - hoặc _). Bỏ `--experiment` để tự tạo ID. Không ghi đè thí nghiệm cũ. Đổi tham số model không cần chạy lại Phase 1–3; đổi feature/reference/preprocessing cần chạy lại phase tương ứng và tạo thí nghiệm mới.

Sau khi chốt lựa chọn bằng validation, thay `tuning-01` bằng ID bạn đã chọn:

```powershell
python -m pypi_metadata_detector --evaluate .\outputs\run-01 --experiment tuning-01 --test --metric --visual
```

Lệnh test không train, không chọn lại model/ngưỡng. Test báo cáo cấu hình tốt nhất theo validation của từng thuật toán; selected_model giữ nguyên lựa chọn validation. Chạy lại cùng lệnh dùng kết quả test đã lưu. Không tiếp tục tuning theo test. Tool không thể ngăn người dùng tạo một thí nghiệm mới sau khi đã xem test; đây là quy định thực nghiệm của nhóm.

## Metric, Top Model, Top Feature và FP/FN

```powershell
python -m pypi_metadata_detector --metric .\outputs\run-01 --experiment tuning-01
python -m pypi_metadata_detector --visual .\outputs\run-01 --experiment tuning-01
```

Bỏ ID để xem thí nghiệm hoàn thành gần nhất của run. Bỏ cả PATH để dùng run gần nhất. Terminal hiện metric và 5 feature đầu mỗi model. HTML offline có bảng metric, Top Model theo metric, Top Feature, FP/FN lọc theo model/loại lỗi/tên, lịch sử trial và xuất CSV.

- Metric: precision/recall/F1 malicious, Macro-F1, Accuracy, ROC-AUC, Average Precision, FP/FN, thời gian fit/predict.
- Average Precision được tính bằng sklearn.average_precision_score, không gọi nhầm là tích phân PR-AUC.
- Linear SVM xuất score_kind=decision: điểm quyết định, không phải xác suất. Các score probability chưa được calibration, không gọi là độ chắc chắn.
- Importance: DT/RF dùng impurity decrease; XGBoost dùng gain; LR/SVM dùng hệ số trên input đã scale; CNB dùng chênh lệch trọng số hai lớp. Đây là ranking toàn model, không giải thích riêng từng sample; không so trực tiếp độ lớn importance giữa các model.
- Bảng sample của thí nghiệm chỉ có prediction trên validation/test đã chạy; không tính train thành metric held-out.
- Nhãn is_typosquatting/target/evidence/label_method không đi vào classifier. Nhãn typosquatting suy từ SpellBound không là ground truth độc lập để đánh giá chính detector đó.

## Nơi lưu kết quả

```text
outputs/<run>/
  extraction.json, analysis.json, preprocessing.json
  encoder.joblib, X_train.npz, X_validation.npz, X_test.npz
  experiments/<ID>/
    training_config.json, experiment.json, status.json
    trials.json, trials.csv
    bundle.joblib, bundle.joblib.sha256
    feature_names.json, splits.csv
    validation_metrics.json, validation_leaderboard.csv
    validation_predictions.csv/json, validation_errors.csv/json
    top_features.json, top_features.csv
    test_metrics.json, test_leaderboard.csv           # chỉ sau --test
    test_predictions.csv/json, test_errors.csv/json  # chỉ sau --test
    metrics.json                                    # sau --metric/--visual
visual/<run>/<ID>/index.html
```

experiment.json lưu seed, cấu hình, phiên bản môi trường, hash dữ liệu/nhãn/split/preprocessing và cấu hình được chọn. trials.json giữ tham số thực tế, lỗi và cảnh báo hội tụ. Cấu hình không hội tụ không được chọn. Có model lỗi thì các model còn lại tiếp tục; đọc failed_trials trước khi báo cáo kết quả.

## Scan sample mới

Dùng bundle local tin cậy do nhóm tạo, kèm file checksum. Thay TEN-RUN/ID bằng giá trị thật:

```powershell
python -m pypi_metadata_detector --extraction .\sample.whl --output .\outputs\scan-01 --bundle .\outputs\TEN-RUN\experiments\ID\bundle.joblib
python -m pypi_metadata_detector --analysis .\outputs\scan-01 --bundle .\outputs\TEN-RUN\experiments\ID\bundle.joblib
python -m pypi_metadata_detector --preprocessing .\outputs\scan-01 --bundle .\outputs\TEN-RUN\experiments\ID\bundle.joblib
python -m pypi_metadata_detector --evaluate .\outputs\scan-01 --bundle .\outputs\TEN-RUN\experiments\ID\bundle.joblib --metric --visual
```

Scan không fit lại. Không nạp joblib từ sample hay nguồn không tin cậy; checksum kiểm tra tính toàn vẹn, không chứng minh nguồn đáng tin.

## Reference và kiểm thử

Phase 2 mặc định dùng 28 target ví dụ. Muốn đồng bộ inventory PyPI, gọi riêng `python -m pypi_metadata_detector reference sync --output .\references`. Không có sync ngầm. `--references` chọn snapshot offline. `--config` là cấu hình Phase 1/2; `--train-config` chỉ cho Phase 4. Inventory PyPI không phải danh sách benign.

```powershell
python -m pip install -e ".[ml,test]"
python -B -m pytest -p no:cacheprovider -q
```

Synthetic fixture chỉ xác minh chức năng, không là metric phát hiện thực. Xem [hướng dẫn thành viên 2](docs/MEMBER2_TRAINING.md), [định dạng cấu hình](docs/TRAINING_CONFIG.md) và [source layout](docs/SOURCE_LAYOUT.md).

Subcommand reference/extract/analyze/train/evaluate/scan cũ vẫn có để tương thích. `train` cũ chỉ RF/DT và có thể fit lại preprocessing; dùng giao diện flag ở trên cho thí nghiệm 1.2.1.

