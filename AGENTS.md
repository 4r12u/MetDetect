# Project instructions

## CLI 1.2.1 — 26/10/2026

Giao diện khuyến nghị: Phase 1 đọc Dataset và --output outputs/RUN; Phase 2–4 nhận thư mục kết quả bước trước (hoặc extraction.json/analysis.json/preprocessing.json tương ứng). Kết quả các phase tích lũy trong cùng run, không sao chép Dataset. --evaluate PATH --model dt hoặc dt,rf,lr/all chọn model trước khi train, giữ grid/params trong --train-config. --test/--bundle dùng model đã chốt. Đường dẫn Dataset kiểu cũ vẫn tương thích. Xem README và docs/SETUP_WINDOWS.md; không dùng đường dẫn dataset ở các ví dụ cũ làm luồng được khuyến nghị.

## Cập nhật đã được người dùng yêu cầu — 26/10/2026

Source 1.2.0 mở rộng Phase 4: DT/RF/LR/LinearSVC/ComplementNB/XGBoost; cấu hình train riêng, tuning grid có giới hạn trên validation, thí nghiệm riêng không ghi đè, test chạy riêng bằng --test. Top Model/Top Feature/FP-FN thuộc reporting. Các hạn chế model RF/DT-only trong tài liệu cũ được thay bởi yêu cầu này; không thay phạm vi metadata-only. Đọc README.md, docs/TRAINING_CONFIG.md và docs/MEMBER2_TRAINING.md cho giao diện hiện hành. Không thay dataset/nhãn khi nâng cấp source.

## Phạm vi hiện hành — 24/10/2026

Đọc [docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md) và [docs/PROJECT_TOOL_PLAN.md](docs/PROJECT_TOOL_PLAN.md) trước khi lập kế hoạch hoặc triển khai.

Quyết định mới của người dùng thay thế toàn bộ kế hoạch static/LLM trước đây. Đây là project môn học ứng dụng ML vào bảo mật, chỉ dùng metadata package PyPI và tín hiệu tương đồng tên.

- Pipeline duy nhất: đọc PKG-INFO/METADATA → tạo tín hiệu metadata/typosquatting → preprocessing → RF/DT và đánh giá.
- Giao diện 1.1.0: --extraction/--analysis/--preprocessing/--evaluate dùng cùng PATH; --metric tổng kết, --visual tạo HTML offline. Artifact phase trong outputs, HTML trong visual. Phase 3 lưu encoder/X, Phase 4 dùng lại không fit preprocessing. Giữ subcommand cũ tương thích. Dataset mới có nhãn/split, đọc tự động manifest.csv/dataset.csv; không suy nhãn từ thư mục.
- Source hiện hành nằm trực tiếp trong pypi_metadata_detector/ ở root; chạy python -m pypi_metadata_detector. Source/entry point pypi_detector 0.5.0 đã được xóa/gỡ theo yêu cầu người dùng.
- Source được chia thành phase1_metadata_extraction, phase2_metadata_analysis, phase3_preprocessing, phase4_ml_classification; xem docs/SOURCE_LAYOUT.md. Chia dataset và fit preprocessing thuộc Phase 3; model/evaluate/predict thuộc Phase 4. Root preprocess.py chỉ hỗ trợ đọc bundle 1.0.0.
- Không đưa Scalpel, AST/CFG/call graph, CodeQL, LLM/provider/skills/refinement, taxonomy hành vi, KG/GNN hoặc CodeBERT trở lại backlog.
- Đọc package như dữ liệu; không cài, build, import hoặc thực thi sample, chạy setup.py, lệnh README, dependency hoặc payload.
- Raw metadata giữ nguyên; phân biệt thiếu trường, giá trị rỗng, placeholder và lỗi đọc/đối chiếu.
- Đặc điểm chuỗi do người dùng đề xuất được phép khảo sát riêng; không gọi password-strength/entropy là bằng chứng obfuscation hoặc dùng ngưỡng để gán nhãn.
- Nhãn từ manifest; không tạo nhãn từ unknown, tên gần giống, lỗi API hoặc việc bị gỡ khỏi PyPI.
- Snapshot PyPI có nguồn/ngày/phiên bản. Danh sách đăng ký không là danh sách benign; kết quả lookup hiện tại không mặc định là feature ML.
- Chia dữ liệu theo package; fit vocabulary/transformer trên train. Giữ test để đánh giá cuối.
- Không thêm yêu cầu tính mới, RQ, ablation hoặc vượt trội paper. Tập trung tool chạy được, feature giải thích được, kiểm thử và demo.
- Tài liệu trước lần thay phạm vi nằm ở docs/history/pre-metadata-20261024/, chỉ là lịch sử; source cũ đã xóa. Dữ liệu demo synthetic không dùng làm metric phát hiện thực.
- Không xóa source, dataset, kết quả cũ hoặc sửa Report/ảnh/caption/citation khi chưa có yêu cầu riêng.
- Khi người dùng gõ /graphify, đọc skill graphify đã cài trước khi làm việc khác.

