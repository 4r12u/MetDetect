# PyPI Metadata Detector 1.2.1

Tool metadata-only cho project AIC211: PKG-INFO/METADATA → tín hiệu metadata/tên → TF-IDF và feature số → phân loại benign/malicious. Không thực thi, cài đặt, build hoặc import package mẫu. Không có LLM trong pipeline này.

## Chuẩn bị môi trường Windows

Mở PowerShell tại thư mục gốc project (nơi có `pyproject.toml`). Nếu chưa có môi trường, xem [SETUP_WINDOWS.md](docs/SETUP_WINDOWS.md). Kích hoạt môi trường và cài tool của nhóm nếu chưa cài:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[ml]"
pypi-metadata --version
pypi-metadata --help
```

`ml` cài thêm XGBoost cho tool. Bỏ `[ml]` nếu chỉ dùng các model scikit-learn. XGBoost thiếu được ghi là trial lỗi, các model khác vẫn chạy. Không cài bất kỳ sample nào trong Dataset.

ZIP source không kèm Dataset, môi trường Python, model hay kết quả cá nhân. Khi chuyển sang thư mục mới, đặt Dataset đã kiểm chứng vào cạnh README này; giữ nguyên cấu trúc archive và manifest. Không cần chuyển sang thư mục source bên trong.

Các lệnh dưới đây dùng `pypi-metadata` sau khi cài tool và kích hoạt môi trường. Nếu chưa nhận diện được lệnh này, thay bằng `python -m pypi_metadata_detector`. Các đường dẫn sample, run và bundle là ví dụ; thay bằng đường dẫn thực tế, đặt trong dấu nháy kép nếu có khoảng trắng.

## Chạy toàn bộ cho showcase

Một lệnh chạy lần lượt bốn phase, vẫn lưu đầy đủ artifact từng phase. Nếu không chỉ định `--output`, tool tự tạo run mới trong `outputs/full-<id>` và in đường dẫn. Với dataset có manifest và nhãn, lệnh sau **train model mới** và đánh giá validation:

```powershell
pypi-metadata -f .\Dataset -m dt,rf
```

Nếu muốn tự đặt tên run và thí nghiệm:

```powershell
pypi-metadata -f .\Dataset -o .\outputs\run-01 -m dt,rf --experiment baseline
```

Bundle của ví dụ này được lưu tại `outputs/run-01/experiments/baseline/bundle.joblib`. Sau khi chọn model bằng validation, chạy `--test` riêng như phần bên dưới; `--full` không tự chạy test. Có thể thêm `--train-config`, `--manifest`, `--config`, hoặc `--references` giống các phase tương ứng.

Để showcase dự đoán mà **không train lại**, dùng bundle tin cậy đã chốt (thay đường dẫn bằng đường dẫn thật):

```powershell
pypi-metadata -f .\sample.whl -b .\models\demo-release\bundle.joblib
```

Viết tắt: `-f` là `--full`, `-b` là `--bundle`, `-m` là `--model`, `-o` là `--output`. Nếu muốn tự đặt output, dùng `-o` với thư mục mới hoặc rỗng. Mỗi lần chạy `-f` không có `-b` tạo thí nghiệm train mới; nếu bỏ `-m`, tool dùng model trong cấu hình hoặc tất cả model mặc định. Scan xuất prediction nhưng không fit lại model hoặc preprocessing.

Dashboard HTML tạo riêng sau khi chạy bằng `pypi-metadata --visual`; lệnh này dùng run gần nhất. Không dùng `--model`, `--train-config`, `--experiment` hoặc `--test` cùng `--full --bundle`. Trong lệnh `--full`, dùng `--metric`/`--visual` không kèm PATH. Tool dừng nếu một phase trả trạng thái lỗi; xem artifact và trạng thái trong thư mục output để kiểm tra. Sample lỗi không được tự gán nhãn. Các phase vẫn đọc package như dữ liệu, không thực thi sample.

## Chạy từng phase để theo dõi

```powershell
pypi-metadata --extraction .\Dataset -o .\outputs\run-01
pypi-metadata --analysis .\outputs\run-01
pypi-metadata --preprocessing .\outputs\run-01
pypi-metadata --evaluate .\outputs\run-01 -m dt,rf --experiment baseline
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
pypi-metadata --evaluate .\outputs\run-01 --train-config .\configs\training-tuning.json --experiment tuning-01
```

Mẫu tuning chạy 27 cấu hình, có thử ngưỡng trên validation. Mỗi thí nghiệm phải có ID mới (chữ, số, dấu - hoặc _). Bỏ `--experiment` để tự tạo ID. Không ghi đè thí nghiệm cũ. Đổi tham số model không cần chạy lại Phase 1–3; đổi feature/reference/preprocessing cần chạy lại phase tương ứng và tạo thí nghiệm mới.

Sau khi chốt lựa chọn bằng validation, thay `tuning-01` bằng ID bạn đã chọn:

```powershell
pypi-metadata --evaluate .\outputs\run-01 --experiment tuning-01 --test
```

Lệnh test không train, không chọn lại model/ngưỡng. Test báo cáo cấu hình tốt nhất theo validation của từng thuật toán; selected_model giữ nguyên lựa chọn validation. Chạy lại cùng lệnh dùng kết quả test đã lưu. Không tiếp tục tuning theo test. Tool không thể ngăn người dùng tạo một thí nghiệm mới sau khi đã xem test; đây là quy định thực nghiệm của nhóm.

## Dashboard: metric, Top Model, Top Feature và FP/FN

```powershell
pypi-metadata --visual
pypi-metadata --visual .\outputs\run-01 --experiment tuning-01
```

Bỏ ID để xem thí nghiệm hoàn thành gần nhất của run. Bỏ cả PATH để dùng run gần nhất. Tool in đường dẫn HTML offline chứa bảng metric, Top Model theo metric, Top Feature, FP/FN lọc theo model/loại lỗi/tên, lịch sử trial và xuất CSV. Các lệnh train/scan ở trên không tự tạo dashboard; metric validation vẫn được tính nội bộ để chọn model.

Tùy chọn `--metric` cũ vẫn có thể in metric và top feature trong terminal khi được gọi rõ ràng; không cần dùng tùy chọn này trong luồng showcase thông thường.

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
python -m pypi_metadata_detector --evaluate .\outputs\scan-01 --bundle .\outputs\TEN-RUN\experiments\ID\bundle.joblib
```

Scan không fit lại. Không nạp joblib từ sample hay nguồn không tin cậy; checksum kiểm tra tính toàn vẹn, không chứng minh nguồn đáng tin.

## Các tùy chọn thường dùng

| Tùy chọn | Công dụng |
|---|---|
| `-f PATH`, `--full PATH` | Chạy lần lượt bốn phase từ dataset hoặc sample. |
| `-o PATH`, `--output PATH` | Chỉ định thư mục kết quả. Với `--full`, thư mục phải mới hoặc rỗng. |
| `-m CODE`, `--model CODE` | Chọn model khi tạo thí nghiệm train; nhiều mã phân tách bằng dấu phẩy. |
| `-b PATH`, `--bundle PATH` | Dùng bundle local tin cậy đã train để dự đoán. |
| `--experiment ID` | Đặt ID thí nghiệm mới hoặc chọn thí nghiệm khi test/xem dashboard. |
| `--train-config PATH` | Chọn cấu hình model, tham số và grid cho thí nghiệm mới. |
| `--manifest PATH` | Chỉ định manifest khi đọc đầu vào. |
| `--config PATH` | Chọn cấu hình Phase 1/2. |
| `--references PATH` | Chọn snapshot tham chiếu offline. |
| `--test` | Đánh giá test riêng của thí nghiệm đã chốt, không train lại. |
| `--visual [PATH]` | Tạo dashboard HTML; bỏ PATH để dùng run gần nhất. |
| `--quiet` | Giảm thông tin tiến trình trên terminal. |

`--help` liệt kê toàn bộ tùy chọn. Các subcommand tương thích cũ có hướng dẫn riêng, ví dụ `pypi-metadata scan --help`.

## Reference và kiểm thử

Phase 2 mặc định dùng 28 target ví dụ. Muốn đồng bộ inventory PyPI, gọi riêng lệnh sau; không có sync ngầm:

```powershell
pypi-metadata reference sync --output .\references
```

`--references` chọn snapshot offline. `--config` là cấu hình Phase 1/2; `--train-config` chỉ cho Phase 4. Inventory PyPI không phải danh sách benign.

### Thử nghiệm top 3.000 target và inventory PyPI

Chuẩn bị reference **một lần**, dùng snapshot lượt tải JSON đã có trong Dataset và lấy inventory hiện tại từ PyPI chính thức. `--output` phải là thư mục chưa tồn tại; lệnh không ghi đè reference cũ:

```powershell
pypi-metadata reference top --input .\Dataset\provenance\sources\top-pypi-packages-30-days.min.json --provenance .\Dataset\provenance\sources\reference_provenance.json --output .\outputs\reference-top3000 --sync-index
```

Snapshot đầu vào phải có `rows` gồm `project`, `download_count`, sắp xếp theo lượt tải giảm dần. Lệnh kiểm tra thứ tự toàn bộ snapshot, chọn 3.000 dòng đầu, chuẩn hóa tên và lưu hash, thời điểm có trong snapshot và số target vào `reference.json`. `--provenance` là tùy chọn; nếu dùng, file phải chứa SHA-256 khớp snapshot và có thể ghi URL, thời điểm lấy dữ liệu và kỳ thống kê khi nguồn cung cấp. Không suy kỳ thống kê từ tên file: kỳ không có bằng chứng được lưu `null`. Đây là snapshot tổng hợp sẵn, không phải lệnh tự query BigQuery. `--sync-index` chỉ truy cập PyPI để lấy inventory tên; bỏ tùy chọn này nếu muốn chuẩn bị offline, khi đó trạng thái inventory là unavailable. Có thể thay `--top 3000` bằng số từ 1 đến 5.000.

Để bổ sung target theo tiêu chí và nguồn đã chốt, cung cấp `--targets .\targets-extra.txt`, mỗi dòng một tên (hoặc CSV cột `name`); tổng số tên duy nhất tối đa 5.000. Danh sách lượt tải và danh sách bổ sung chỉ phục vụ lựa chọn target, không tự gán nhãn benign/malicious. Lưu snapshot reference và nguồn target cùng kết quả thí nghiệm; không chọn target theo lỗi trên test.

Chạy một run mới để so sánh với TC0:

```powershell
pypi-metadata -f .\Dataset -o .\outputs\run-top3000 -m all --experiment baseline --references .\outputs\reference-top3000
pypi-metadata --visual .\outputs\run-top3000 --experiment baseline
```

Đây là lần train mới; test vẫn chạy riêng sau khi chốt. Dùng `-m all` để thử sáu model như baseline `testcase0`, hoặc chọn model bằng `-m` nếu cần. Scan bằng bundle mới có thể dùng cùng reference để đối chiếu inventory:

```powershell
pypi-metadata -f .\sample.whl -b .\outputs\run-top3000\experiments\baseline\bundle.joblib --references .\outputs\reference-top3000
```

Nếu bỏ `--references` khi scan, tool vẫn dùng target đã lưu trong bundle nhưng inventory có thể unavailable. Reference phải có target khớp bundle. Top 3.000 không đảm bảo bao phủ mọi target và không thêm quy tắc combosquatting. Quy tắc hiện tại trả về `exact_target` và không xét tiếp các target khác khi tên sample trùng một target; đây không phải xác minh package an toàn. Nếu target snapshot mới hơn mẫu lịch sử, ghi rõ điều đó khi diễn giải đánh giá. Tăng từ 28 lên 3.000 target có thể làm Phase 2 mất thời gian hơn; lệnh vẫn chạy offline sau bước chuẩn bị reference.

```powershell
python -m pip install -e ".[ml,test]"
python -B -m pytest -p no:cacheprovider -q
```

Synthetic fixture chỉ xác minh chức năng, không là metric phát hiện thực. Xem [hướng dẫn thành viên 2](docs/MEMBER2_TRAINING.md), [định dạng cấu hình](docs/TRAINING_CONFIG.md) và [source layout](docs/SOURCE_LAYOUT.md).

Subcommand reference/extract/analyze/train/evaluate/scan cũ vẫn có để tương thích. `train` cũ chỉ RF/DT và có thể fit lại preprocessing; dùng giao diện flag ở trên cho thí nghiệm 1.2.1.

