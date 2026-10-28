# Bàn giao thành viên 2 — huấn luyện và chọn model

## Đầu vào cần nhận

- Source 1.2.1; Python >=3.10; cài `python -m pip install -e ".[ml]"`.
- Dataset đã kiểm chứng, phiên bản/hash, manifest nhãn benign/malicious và split đã chốt.
- Reference và cấu hình Phase 1/2 đã thống nhất; không đổi chúng trong lúc so sánh model.
- Kết quả Phase 1–3 hoặc tự chạy ba lệnh đầu trong README. Không cần chạy lại chúng khi chỉ đổi model/tham số.

## Quy trình

1. Chạy `--evaluate .\outputs\run-01 --model all --train-config .\configs\training-default.json --experiment baseline --metric --visual` để lấy baseline sáu model.
2. Đọc `trials.json`: kiểm tra model nào thất bại, thiếu thư viện hoặc không hội tụ. Lần chạy có một model lỗi vẫn giữ các model còn lại; không ghi model lỗi vào bảng như điểm 0.
3. Sao chép training-tuning.json thành cấu hình riêng, chọn grid nhỏ và chạy với ID mới. Tuning mẫu gồm 27 cấu hình. Không đổi split, nhãn hay vocabulary theo kết quả model.
4. So sánh validation, mặc định chọn F1 malicious. Xem Recall, FP/FN và thời gian. Ghi lại lựa chọn, tham số và ngưỡng trước khi xem test.
5. Chạy `--evaluate .\outputs\run-01 --experiment ID-DA-CHON --test --metric --visual`. Thay ID-DA-CHON bằng ID thật. Không train lại và không chọn model theo điểm test.
6. Nộp bảng kết quả validation/test, Top Feature, phân tích FP/FN, cấu hình và bundle đã chọn. Không diễn giải feature importance thành quan hệ nhân quả.

## Hồ sơ cần nộp

- Thư mục thí nghiệm hoàn chỉnh dưới outputs/<run>/experiments/<ID>/, gồm checksum bundle.
- File cấu hình đã dùng; dataset/preprocessing identity và seed (có trong experiment.json).
- validation_leaderboard.csv, test_leaderboard.csv; metric đầy đủ và các trial đã thử.
- top_features.csv và ít nhất một nhận xét về nhóm metadata, tên hoặc từ TF-IDF model dựa vào.
- test_errors.csv với vài trường hợp FP/FN được đối chiếu metadata. Không tự sửa nhãn vì model dự đoán khác.
- HTML offline trong visual/<run>/<ID>/ và lý do chọn model dựa trên validation.

## Quy định phối hợp

Mỗi người sao chép source vào thư mục riêng hoặc chỉ định run riêng; không cùng ghi vào một run. Các experiment ID khác nhau bảo vệ kết quả khỏi ghi đè, nhưng không phải hệ thống khóa cho nhiều tiến trình cùng chạy một run. Không chỉnh trực tiếp model/JSON/ma trận cache đã lưu. Nếu dataset đổi phiên bản, tạo run mới và chạy lại các phase liên quan.

Tuning dùng cùng holdout validation nên quá nhiều lần thử có thể học theo validation. Giữ grid gọn và báo trung thực số trial. Không mặc định gọi model có điểm cao nhất test là model được chọn. Source snapshot PyPI không xác nhận benign; nhãn typosquatting từ heuristic không phải ground truth độc lập.

Synthetic fixture dùng trong kiểm thử source chỉ chứng minh tool hoạt động. Các metric đó không được mang đi presentation như hiệu quả bảo mật.

