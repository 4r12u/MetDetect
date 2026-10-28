# Phạm vi project — PyPI Metadata Detector

## CLI 1.2.1 — 26/10/2026

Phase 2–4 nhận thư mục output của bước trước hoặc JSON marker tương ứng; kết quả tích lũy trong một run. Phase 4 chọn thuật toán bằng --model dt/rf/lr/svm/cnb/xgb hoặc danh sách dấu phẩy/all. Test tách riêng và không đổi model đã chốt. Hướng dẫn cài đặt: SETUP_WINDOWS.md. Không đổi pipeline/feature/dataset trong lần nâng cấp giao diện này.

## Cập nhật 26/10/2026 — source 1.2.0

Theo yêu cầu mới của người dùng, Phase 4 hỗ trợ DT, RF, Logistic Regression, Linear SVM, Complement Naive Bayes và XGBoost. Tuning dùng validation, test chỉ chạy riêng sau khi chốt. Thêm lịch sử thí nghiệm, xếp hạng model theo metric, Top Feature và FP/FN. Các đoạn RF/DT-only bên dưới mô tả baseline ban đầu, không hạn chế phần mở rộng này. Pipeline metadata-only và bảo vệ train/test vẫn giữ. Giao diện và đầu ra mới xem README.md, TRAINING_CONFIG.md và MEMBER2_TRAINING.md.

Chốt ngày 24/10/2026 theo quyết định mới nhất của người dùng.

## Mục tiêu

Xây tool CLI ứng dụng ML vào bảo mật để hỗ trợ phân loại package PyPI từ metadata và phát hiện tên dễ nhầm với package tham chiếu. Đây là project môn học: giải thích thiết kế, xây tool, kiểm thử, đánh giá và demo; không yêu cầu tạo tri thức mới.

Tài liệu này và [PROJECT_TOOL_PLAN.md](PROJECT_TOOL_PLAN.md) thay thế toàn bộ kế hoạch trước đó. Không mang các yêu cầu của bản lịch sử trở lại phạm vi hiện hành.

## Bốn phase duy nhất

| Phase | Công việc | Đầu ra |
| --- | --- | --- |
| 1. Metadata extraction | Đọc PKG-INFO/METADATA; chuẩn hóa cấu trúc đầu ra, giữ nguyên giá trị gốc | metadata.json và status.json theo sample |
| 2. Metadata analysis | Phân loại trạng thái trường; đối chiếu snapshot; tín hiệu tương đồng tên | signals.json và thông tin đối chiếu |
| 3. Preprocessing | Feature số/nhị phân, TF-IDF văn bản, ghép X; fit trên train | fitted preprocessing và ma trận/feature mapping |
| 4. ML classification | Train RF/DT, validation, đánh giá test, scan bằng fitted bundle | model bundle, metrics, predictions |

Phase 2 là xử lý có quy tắc; không gọi LLM. Dự đoán malicious/benign cuối do classifier học từ nhãn dataset. Tên gần giống hoặc thiếu metadata không tự xác định nhãn.

## Đầu vào và dữ liệu

- Nhận metadata trực tiếp, folder sample hoặc archive .whl/.zip/.tar.gz.
- Trong archive chỉ đọc metadata liên quan; không thực thi/cài/import/build package hoặc tải dependency/payload.
- Nhận manifest tối thiểu sample_id, path, label. Label chỉ nhận benign/malicious ở luồng train/evaluate; scan không yêu cầu nhãn.
- Không khóa số mẫu hoặc đường dẫn vào dataset cũ. Có thể dùng metadata trích từ dataset đã có và kế thừa nhãn/nguồn phù hợp.
- Một artifact/version là một sample. Các phiên bản cùng tên package được nhóm khi chia train/validation/test. Ghi nhận metadata trùng hoặc nhãn mâu thuẫn.
- Input lỗi hoặc thiếu metadata là trạng thái xử lý, không tự tạo sample benign.
- Giá trị mô tả, tên tác giả và URL giữ nguyên ở dữ liệu raw; không truy cập URL lấy từ sample.

## Hợp đồng metadata

Giữ Metadata-Version, Name, Version, Summary, Home-page, Author, Author-email, License, Description; thêm Project-URL, Requires-Python, Requires-Dist và License-Expression khi có. Trường lặp giữ dạng danh sách. Version là chuỗi; schema_version của tool tách khỏi Metadata-Version trong package.

Mỗi trường được phân biệt missing, empty, placeholder, present. JSON null biểu diễn trường không tồn tại; chuỗi UNKNOWN/None nguyên văn vẫn nằm trong raw metadata và được đánh dấu ở Phase 2.

Regex có thể dùng nhận diện/chuẩn hóa giá trị và tín hiệu. Dùng email.parser của Python để đọc header nhiều dòng, header lặp và Description trong phần thân; không xây một ngôn ngữ parser mới.

## Feature và NLP

Baseline gồm cờ hiện diện/placeholder của từng trường, tín hiệu biến đổi tên và TF-IDF của Summary + Description. Tên nguyên văn, version, author/email, URL, đường dẫn, sample_id, nhãn và split giữ ngoài X mặc định để hạn chế học thuộc danh tính.

Tập tên đăng ký lấy từ PyPI official là inventory. Tập tên mục tiêu cho typosquatting phải được chọn và lưu riêng; không coi mọi tên trên PyPI là benign. Chuẩn hóa tên theo PyPA trước khi đối chiếu.

Entropy/đặc điểm ký tự do người dùng đề xuất nằm trong profile thử nghiệm riêng, tắt ở baseline. Không gọi các giá trị này là bằng chứng obfuscation, không áp điểm password strength hoặc ngưỡng entropy để tự gán malicious. Lưu đủ định nghĩa và xử lý chuỗi rỗng; không suy intent từ một giá trị.

## Đối chiếu PyPI

- Sync có chủ đích rồi chạy offline với snapshot đã chốt, ghi nguồn/ngày/hash.
- Metadata bản phát hành phải đối chiếu cùng name/version, không so artifact cũ với latest rồi báo giả mạo.
- Author/Author-email là dữ liệu khai báo, không là danh tính maintainer đã được xác thực.
- Phân biệt match, mismatch, unavailable và lookup_error.
- 404/takedown/lỗi mạng và mức độ đầy đủ của snapshot là thông tin audit, không là feature độc hại mặc định.
- Name inventory không có popularity. Muốn mô phỏng SpellBound đầy đủ cần nguồn lượt tải riêng; bản đầu chỉ kế thừa tín hiệu tên.

## Model và đánh giá

- Bắt buộc: Random Forest, Decision Tree. Chọn bằng validation; test dùng sau khi chốt.
- Fit TF-IDF/vocabulary/transformer trên train; scan dùng cùng fitted bundle.
- Báo precision, recall, F1, confusion matrix và số sample đủ điều kiện/bị bỏ qua.
- Cảnh báo typosquatting tách khỏi dự đoán malicious/benign. Chỉ báo metric typosquatting khi có annotation cho nhiệm vụ đó.
- Feature importance của model cây không thay thế lời giải thích nhân quả.
- Không dùng test để tạo reference targets, vocabulary hoặc chọn ngưỡng.

## Ngoài phạm vi bản đầu

Scalpel, AST/CFG/call graph, CodeQL, LLM/API/local/Codex CLI refinement, taxonomy hành vi, KG/GNN, CodeBERT, phân tích động, web server và các model bổ sung không thuộc tool mới. Báo cáo HTML offline (--visual) được bổ sung theo yêu cầu 24/10/2026.

## Giao diện 1.1.0

--extraction PATH, --analysis PATH, --preprocessing PATH và --evaluate PATH là bốn bước độc lập dùng cùng đầu vào. Manifest được nhận tự động, nhãn/split được giữ và kiểm tra. Phase 3 lưu encoder/X; Phase 4 dùng lại, train/chọn bằng validation rồi đánh giá test. Với --bundle, Phase 3 chỉ transform và Phase 4 predict. --metric tổng kết terminal/JSON; --visual tạo HTML trong visual. Artifact phase ở outputs. Không có nhãn/model phù hợp thì báo thiếu dữ liệu, không tạo nhãn/metric giả.

Ý tưởng README/source consistency người dùng nêu được ghi lại là khả năng xem xét sau khi hoàn thành bốn phase, không là hạng mục cần xây hiện tại.

## Source và tài liệu

Tool mới đã được triển khai trong pypi_metadata_detector/ ở root. Phiên bản 1.0.1 chia source thành bốn thư mục phase theo [SOURCE_LAYOUT.md](SOURCE_LAYOUT.md); cli/common giữ phần điều phối/hạ tầng. Source/tool cài đặt 0.5.0 đã bị xóa/gỡ theo yêu cầu tiếp theo của người dùng. Dataset và venv giữ lại; không migrate model/cache/feature của pipeline static cũ. Bundle metadata 1.0.0 vẫn đọc được.

Lịch sử trước thay phạm vi: [HISTORY.md](history/pre-metadata-20261024/HISTORY.md). Báo cáo, ảnh/caption/citation chưa được chỉnh sửa bởi lần lập kế hoạch này.

