# PyPI Metadata Detector — trạng thái triển khai

## 1.2.1 — 26/10/2026

CLI nhận thư mục output hoặc JSON marker của phase trước cho Phase 2–4, có --model/--models chọn một/nhiều/all model, giữ tham số/grid trong file. In lệnh bước tiếp và có hướng dẫn setup Windows tại SETUP_WINDOWS.md. Dataset không thay đổi. Các phần dưới giữ lịch sử phiên bản trước.

## 1.2.0 — 26/10/2026

Đã triển khai sáu model, train config độc lập, tuning grid có giới hạn, ngưỡng chọn trên validation, thư mục thí nghiệm không ghi đè, test tách riêng, metric mở rộng và ranking, Top Feature native, FP/FN, HTML/CSV và hướng dẫn thành viên 2. Source không thay dataset/nhãn. Xem RELEASE_NOTES_1.2.0.md và TRAINING_CONFIG.md. Các phần bên dưới là trạng thái lịch sử 1.1.0, không dùng số dataset hoặc luồng tự chạy test đó làm trạng thái hiện hành.

## 1.1.0 — 24/10/2026 (lịch sử)

## Giao diện mới

Đã thêm --extraction / --analysis / --preprocessing / --evaluate dùng chung PATH, nhận manifest/dataset.csv tự động và giữ nhãn/split. Phase 3 lưu encoder/X; Phase 4 dùng lại để train/test hoặc predict bằng --bundle. --metric hiện tổng kết/JSON; --visual tạo HTML offline có bộ lọc, RF/DT và confusion matrix. Output ở outputs; HTML ở visual. Các subcommand 1.0.1 vẫn hỗ trợ. Kết quả cũ không khớp dữ liệu được đánh dấu cần chạy lại.

Dataset hiện dùng là Dataset/ với 2.292 artifact có nhãn/split. Không thay đổi dataset hoặc tự gán nhãn. Các đoạn mini-200 bên dưới ghi lại QA bản trước. Xem FLAGS_QA.json cho QA lần nâng cấp này khi hoàn tất.

## Bố trí bốn phase

Đã chuyển extract vào Phase 1, reference/signals vào Phase 2, dataset/split/encoder/prepare_training vào Phase 3 và RF/DT/evaluate/predict vào Phase 4. Xem [SOURCE_LAYOUT.md](SOURCE_LAYOUT.md). CLI và schema không đổi; root preprocess.py giữ import tương thích cho bundle 1.0.0. QA riêng của lần chia source nằm trong PHASE_LAYOUT_QA.json.

## Đã triển khai

- Source metadata mới ở pypi_metadata_detector/; Python module và console entry point pypi-metadata.
- Parser giữ Unicode, header lặp/folded, body Description và trạng thái thiếu/rỗng/placeholder.
- Đọc wheel/ZIP/tar trực tiếp, kiểm tra giới hạn và đường dẫn; nhận ZIP mang đuôi tar.gz, bỏ directory mang tên METADATA.
- Reference official PyPI với sync explicit, exact-release lookup tùy chọn; analyze/scan offline.
- Feature metadata, sáu tín hiệu tên, edit distance, TF-IDF; lexical_experiment riêng tắt mặc định.
- Group-aware splits, train-only preprocessing, RF/DT, validation selection, test evaluation.
- Bundle kèm checksum và config/target/version checks; scan không fit/không cần nhãn.
- Progress từng sample, output JSON/CSV, template nhãn và demo synthetic.

## Trạng thái dữ liệu

Người dùng sẽ dựng lại nhãn sau. Không gán nhãn cho mini_200_mixed và không công bố metric phát hiện thực.

Batch metadata mini 200 chạy được extraction/analyze. Số kiểm thử và xác minh checksum cuối cùng được ghi trong METADATA_TOOL_QA.json khi hoàn tất QA.

Demo/test synthetic chỉ xác nhận luồng phần mềm. RF/DT cần huấn luyện bằng nhãn thật trước khi dùng để kết luận package.

## Xóa tool cũ

Source .py, tài nguyên QL/skill/prompt, scripts/tests/config/schema cũ đã xóa bằng bản vá liệt kê từng file; cache biên dịch cũ được dọn riêng. Bản cài aic211-pypi-detector 0.5.0 đã gỡ khỏi venv; dependency mới được khai báo riêng.

Dataset và venv giữ nguyên theo mục đích sử dụng. Checksum dataset trước thay source được ghi ở DATASET_BEFORE_RESET.json để đối chiếu.

## Hướng dẫn hiện hành

[README](../README.md) có lệnh thực tế. Các lệnh/namespace cũ không còn áp dụng. Thiết kế trong PROJECT_TOOL_PLAN.md được cập nhật với bố trí root đơn giản hơn.

